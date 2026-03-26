#!/usr/bin/env python3
"""
Layer 3 Correlation Engine - Threat confirmation via contextual analysis.

Consumes high-severity anomalies from Redis (pushed by Layer 2), queries
a production Elasticsearch/OpenSearch for correlated events, builds an
enriched context, sends it to the LLM for final threat assessment, and
writes confirmed threats to the logs-threats index.

Example flow:
  1. Layer 2 flags "Failed password for root from 185.220.101.42" as high severity
  2. Layer 3 queries prod ES: "show me all events from 185.220.101.42 in the last 5 min"
  3. Finds: 15 failed logins + 1 successful login as root
  4. Sends enriched context to LLM: "Is this a confirmed brute force with compromise?"
  5. LLM responds: confirmed=true, severity=critical, narrative="..."
  6. Result indexed to logs-threats for SIEM/alerting
"""

import os
import re
import sys
import json
import time
import signal
import logging
import datetime
from threading import Event
from queue import Queue, Empty

import redis as redispy
import requests
from opensearchpy import OpenSearch
from elasticsearch import Elasticsearch

# ---------------------------------------------------------------------------
# Configuration
# ---------------------------------------------------------------------------
REDIS_HOST = os.getenv("REDIS_HOST", "redis://redis:6379")
L3_QUEUE_KEY = os.getenv("L3_QUEUE_KEY", "layer3:queue")

# Ollama (via HAProxy load balancer)
OLLAMA_HOST = os.getenv("OLLAMA_HOST", "http://haproxy:11434")
L3_LLM_MODEL = os.getenv("L3_LLM_MODEL", os.getenv("LLM_MODEL", "qwen2.5:3b"))

# Production Elasticsearch for contextual queries
PROD_ES_HOST = os.getenv("PROD_ES_HOST", "")
PROD_ES_USER = os.getenv("PROD_ES_USER", "")
PROD_ES_PASS = os.getenv("PROD_ES_PASS", "")
PROD_ES_INDEX = os.getenv("PROD_ES_INDEX", "logs-*")
PROD_ES_VERIFY_CERTS = os.getenv("PROD_ES_VERIFY_CERTS", "false").lower() == "true"

# PoC OpenSearch (for writing results and fallback queries)
OPENSEARCH_HOST = os.getenv("OPENSEARCH_HOST", "http://opensearch:9200")

# Correlation settings
CORRELATION_WINDOW_SEC = int(os.getenv("CORRELATION_WINDOW_SEC", "300"))
MAX_CORRELATED_EVENTS = int(os.getenv("MAX_CORRELATED_EVENTS", "100"))

# Only process events with these LLM severities from Layer 2
L3_SEVERITY_FILTER = os.getenv("L3_SEVERITY_FILTER", "high,critical").split(",")

# Index for confirmed threats
IDX_THREATS = "logs-threats"

# ---------------------------------------------------------------------------
# Logging
# ---------------------------------------------------------------------------
logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s [%(levelname)s] %(message)s",
    stream=sys.stdout,
)
log = logging.getLogger("layer3-engine")

shutdown_event = Event()


def _handle_signal(signum, frame):
    log.info("Received signal %s, shutting down ...", signum)
    shutdown_event.set()


signal.signal(signal.SIGINT, _handle_signal)
signal.signal(signal.SIGTERM, _handle_signal)

# ---------------------------------------------------------------------------
# LLM prompt for Layer 3 correlation analysis
# ---------------------------------------------------------------------------
L3_PROMPT_TEMPLATE = """You are a senior security analyst performing threat correlation.
You have access to the original anomaly alert and correlated events from the
environment's log history.

ORIGINAL ALERT (from automated Layer 2 analysis):
- Log entry: {log_line}
- Host: {hostname}
- Process: {process}
- Layer 2 threat category: {l2_threat_category}
- Layer 2 severity: {l2_severity}
- Layer 2 explanation: {l2_explanation}
- Anomaly score: {anomaly_score}

CORRELATED EVENTS (last {window_sec} seconds, same source/host):
{correlated_events}

TIMELINE SUMMARY:
- Total correlated events found: {correlated_count}
- Failed auth attempts: {failed_auth_count}
- Successful auth attempts: {success_auth_count}
- Unique source IPs: {unique_ips}
- Unique target hosts: {unique_hosts}

Based on the correlated events, provide a final threat assessment.
Consider multi-step attack patterns:
- Brute force: many failed logins from same IP, especially if followed by success
- Privilege escalation: sudo/su failures followed by success
- Lateral movement: authentication from unusual internal IPs after initial compromise
- Service disruption: repeated crashes or restarts of the same service

Respond in this exact JSON format (no markdown, no extra text):
{{"confirmed": true, "attack_type": "<specific type e.g. brute_force_success, brute_force_attempt, privilege_escalation_confirmed, service_disruption, false_positive>", "narrative": "<2-3 sentence attack narrative based on the evidence>", "immediate_actions": ["<action 1>", "<action 2>"], "confidence_pct": 85, "severity": "<critical/high/medium/low>", "evidence_summary": "<1-2 sentence summary of key evidence>"}}"""

# ---------------------------------------------------------------------------
# IP extraction regex
# ---------------------------------------------------------------------------
IP_RE = re.compile(r"\b(?:\d{1,3}\.){3}\d{1,3}\b")


def extract_ips(text: str) -> list[str]:
    """Extract all IP addresses from text."""
    return list(set(IP_RE.findall(text)))


# ---------------------------------------------------------------------------
# Elasticsearch / OpenSearch clients
# ---------------------------------------------------------------------------
def create_prod_es_client() -> Elasticsearch | None:
    """Create a client for the production Elasticsearch."""
    if not PROD_ES_HOST:
        log.warning("PROD_ES_HOST not configured. Layer 3 ES correlation disabled.")
        return None

    try:
        kwargs = {
            "hosts": [PROD_ES_HOST],
            "verify_certs": PROD_ES_VERIFY_CERTS,
            "ssl_show_warn": False,
            "request_timeout": 30,
        }
        if PROD_ES_USER and PROD_ES_PASS:
            kwargs["basic_auth"] = (PROD_ES_USER, PROD_ES_PASS)

        client = Elasticsearch(**kwargs)
        info = client.info()
        log.info("Production ES connected: %s", info.get("version", {}).get("number", "unknown"))
        return client
    except Exception as e:
        log.warning("Failed to connect to production ES at %s: %s", PROD_ES_HOST, e)
        return None


def create_opensearch_client() -> OpenSearch:
    """Create client for the PoC OpenSearch (for writing results)."""
    from urllib.parse import urlparse
    parsed = urlparse(OPENSEARCH_HOST)
    host = parsed.hostname or "localhost"
    port = parsed.port or 9200
    scheme = parsed.scheme or "http"

    return OpenSearch(
        hosts=[{"host": host, "port": port}],
        http_compress=True,
        use_ssl=(scheme == "https"),
        verify_certs=False,
        ssl_show_warn=False,
        timeout=30,
    )


def wait_for_opensearch(client: OpenSearch, max_retries: int = 30):
    """Wait until OpenSearch is ready."""
    for i in range(max_retries):
        try:
            client.info()
            log.info("OpenSearch ready.")
            return True
        except Exception:
            log.info("Waiting for OpenSearch (attempt %d/%d)...", i + 1, max_retries)
            time.sleep(5)
    return False


def setup_threats_index(client: OpenSearch):
    """Create the logs-threats index if it doesn't exist."""
    mapping = {
        "mappings": {
            "properties": {
                "@timestamp": {"type": "date"},
                "original_anomaly_id": {"type": "keyword"},
                "original_log_line": {"type": "text"},
                "hostname": {"type": "keyword"},
                "process": {"type": "keyword"},
                "source_ips": {"type": "keyword"},
                "l2_threat_category": {"type": "keyword"},
                "l2_severity": {"type": "keyword"},
                "l2_explanation": {"type": "text"},
                "anomaly_score": {"type": "float"},
                "confirmed": {"type": "boolean"},
                "attack_type": {"type": "keyword"},
                "narrative": {"type": "text"},
                "immediate_actions": {"type": "text"},
                "confidence_pct": {"type": "integer"},
                "severity": {"type": "keyword"},
                "evidence_summary": {"type": "text"},
                "correlated_events_count": {"type": "integer"},
                "failed_auth_count": {"type": "integer"},
                "success_auth_count": {"type": "integer"},
                "correlation_window_sec": {"type": "integer"},
                "l3_raw_response": {"type": "text"},
            }
        },
        "settings": {
            "number_of_shards": 1,
            "number_of_replicas": 0,
        }
    }

    try:
        if not client.indices.exists(index=IDX_THREATS):
            client.indices.create(index=IDX_THREATS, body=mapping)
            log.info("Created index: %s", IDX_THREATS)
        else:
            log.info("Index already exists: %s", IDX_THREATS)
    except Exception as e:
        log.warning("Failed to create index %s: %s", IDX_THREATS, e)


# ---------------------------------------------------------------------------
# Correlation queries against production ES
# ---------------------------------------------------------------------------
def query_correlated_events(es_client: Elasticsearch, anomaly: dict,
                            window_sec: int, max_events: int) -> dict:
    """
    Query production ES for events correlated to the anomaly.

    Returns a dict with:
      - events: list of correlated log lines
      - failed_auth_count: number of auth failure events
      - success_auth_count: number of successful auth events
      - unique_ips: list of unique source IPs
      - unique_hosts: list of unique hostnames
    """
    result = {
        "events": [],
        "failed_auth_count": 0,
        "success_auth_count": 0,
        "unique_ips": set(),
        "unique_hosts": set(),
    }

    if es_client is None:
        result["unique_ips"] = list(result["unique_ips"])
        result["unique_hosts"] = list(result["unique_hosts"])
        return result

    # Extract context from the anomaly
    hostname = anomaly.get("hostname", "")
    message = anomaly.get("message", anomaly.get("original_log_line", ""))
    source_ips = extract_ips(message)
    process = anomaly.get("process", "")

    # Build the ES query - search for related events
    time_range = {"range": {"@timestamp": {"gte": f"now-{window_sec}s"}}}

    # Strategy: query by source IP (if found) OR by hostname+process
    should_clauses = []
    if source_ips:
        for ip in source_ips:
            should_clauses.append({"match": {"message": ip}})
    if hostname:
        should_clauses.append({
            "bool": {
                "must": [
                    {"match": {"message": hostname}},
                ]
            }
        })

    if not should_clauses:
        log.warning("No correlation criteria found for anomaly.")
        result["unique_ips"] = list(result["unique_ips"])
        result["unique_hosts"] = list(result["unique_hosts"])
        return result

    query = {
        "query": {
            "bool": {
                "must": [time_range],
                "should": should_clauses,
                "minimum_should_match": 1,
            }
        },
        "sort": [{"@timestamp": {"order": "asc"}}],
        "size": max_events,
        "_source": ["@timestamp", "message", "hostname"],
    }

    try:
        resp = es_client.search(index=PROD_ES_INDEX, body=query)
        hits = resp.get("hits", {}).get("hits", [])

        for hit in hits:
            src = hit.get("_source", {})
            msg = src.get("message", "")
            ts = src.get("@timestamp", "")
            host = src.get("hostname", "")

            result["events"].append(f"[{ts}] {host}: {msg}")
            result["unique_hosts"].add(host)

            # Extract IPs from correlated events
            for ip in extract_ips(msg):
                result["unique_ips"].add(ip)

            # Count auth events
            msg_lower = msg.lower()
            if any(kw in msg_lower for kw in ["failed password", "authentication fail",
                                                "invalid user", "auth fail"]):
                result["failed_auth_count"] += 1
            if any(kw in msg_lower for kw in ["accepted password", "accepted publickey",
                                                "session opened"]):
                result["success_auth_count"] += 1

        log.info("Correlation query returned %d events (failed_auth=%d, success_auth=%d)",
                 len(hits), result["failed_auth_count"], result["success_auth_count"])

    except Exception as e:
        log.warning("ES correlation query failed: %s", e)

    # Convert sets to lists for JSON serialization
    result["unique_ips"] = list(result["unique_ips"])
    result["unique_hosts"] = list(result["unique_hosts"])
    return result


# ---------------------------------------------------------------------------
# LLM query (same approach as Layer 2 but with different prompt)
# ---------------------------------------------------------------------------
def query_llm(prompt: str) -> dict | None:
    """Send prompt to Ollama via HAProxy and parse JSON response."""
    text = ""
    try:
        log.debug("Sending L3 LLM request to %s model=%s", OLLAMA_HOST, L3_LLM_MODEL)
        resp = requests.post(
            f"{OLLAMA_HOST}/api/generate",
            json={
                "model": L3_LLM_MODEL,
                "prompt": prompt,
                "stream": False,
                "think": False,
                "options": {
                    "temperature": 0.1,
                    "num_predict": 1024,  # Layer 3 needs more tokens for narrative
                },
            },
            timeout=300,  # 5 min timeout for larger context
        )
        resp.raise_for_status()
        raw_resp = resp.json()
        text = raw_resp.get("response", "")
        thinking = raw_resp.get("thinking", "")

        if thinking and not text:
            log.warning("L3 LLM spent all tokens on thinking (%d chars), no response. "
                        "Model may not support think:false.", len(thinking))
            return None

        if not text:
            log.warning("L3 LLM returned empty response (eval_count=%s)",
                        raw_resp.get("eval_count", "?"))
            return None

        # Strip thinking blocks
        text = re.sub(r"<think>.*?</think>", "", text, flags=re.DOTALL)
        text = text.strip()

        # Strip markdown code blocks
        if text.startswith("```"):
            text = re.sub(r"^```(?:json)?\s*", "", text)
            text = re.sub(r"\s*```$", "", text)

        # Extract JSON object - use greedy match to handle nested braces
        # Find the first { and the last } to capture the full JSON object
        first_brace = text.find("{")
        last_brace = text.rfind("}")
        if first_brace != -1 and last_brace > first_brace:
            text = text[first_brace:last_brace + 1]

        result = json.loads(text)
        log.debug("L3 LLM parsed successfully: confirmed=%s, attack_type=%s",
                  result.get("confirmed"), result.get("attack_type"))
        return result
    except requests.exceptions.ConnectionError as e:
        log.warning("Ollama/HAProxy not reachable at %s: %s", OLLAMA_HOST, e)
        return None
    except requests.exceptions.HTTPError as e:
        log.warning("Ollama returned HTTP error: %s", e)
        return None
    except json.JSONDecodeError as e:
        log.warning("Failed to parse L3 LLM JSON: %s (response: %.500s)", e, text)
        return None
    except Exception as e:
        log.warning("L3 LLM query failed: %s", e, exc_info=True)
        return None


# ---------------------------------------------------------------------------
# Main processing loop
# ---------------------------------------------------------------------------
def main():
    log.info("=" * 60)
    log.info("Layer 3 Correlation Engine - Starting up")
    log.info("=" * 60)
    log.info("Config: REDIS_HOST=%s", REDIS_HOST)
    log.info("Config: L3_QUEUE_KEY=%s", L3_QUEUE_KEY)
    log.info("Config: OLLAMA_HOST=%s", OLLAMA_HOST)
    log.info("Config: L3_LLM_MODEL=%s", L3_LLM_MODEL)
    log.info("Config: PROD_ES_HOST=%s", PROD_ES_HOST or "(not configured)")
    log.info("Config: PROD_ES_INDEX=%s", PROD_ES_INDEX)
    log.info("Config: CORRELATION_WINDOW_SEC=%d", CORRELATION_WINDOW_SEC)
    log.info("Config: L3_SEVERITY_FILTER=%s", L3_SEVERITY_FILTER)

    # --- Initialize ---
    os_client = create_opensearch_client()
    if not wait_for_opensearch(os_client):
        sys.exit(1)
    setup_threats_index(os_client)

    prod_es = create_prod_es_client()

    # Connect to Redis
    r = None
    for attempt in range(30):
        try:
            r = redispy.Redis.from_url(REDIS_HOST, decode_responses=True)
            r.ping()
            log.info("Redis connected.")
            break
        except Exception as e:
            log.info("Waiting for Redis (attempt %d/30): %s", attempt + 1, e)
            time.sleep(2)

    if r is None:
        log.error("Could not connect to Redis.")
        sys.exit(1)

    # Check queue backlog
    qlen = r.llen(L3_QUEUE_KEY)
    if qlen > 0:
        log.info("Layer 3 queue has %d events waiting.", qlen)

    log.info("Layer 3 engine ready. Waiting for high-severity events...")

    total_processed = 0
    total_confirmed = 0

    # --- Main loop ---
    while not shutdown_event.is_set():
        try:
            # BLPOP from the Layer 3 queue (1 second timeout)
            result = r.blpop(L3_QUEUE_KEY, timeout=1)
            if result is None:
                continue

            _, raw_data = result

            try:
                anomaly = json.loads(raw_data)
            except json.JSONDecodeError:
                log.warning("Invalid JSON in Layer 3 queue: %.200s", raw_data)
                continue

            total_processed += 1
            doc_id = anomaly.get("doc_id", "unknown")
            hostname = anomaly.get("hostname", "unknown")
            l2_category = anomaly.get("llm_threat_category", "unknown")
            l2_severity = anomaly.get("llm_severity", "unknown")

            log.info(
                "Processing [%s/%s] from %s (doc: %s)",
                l2_category, l2_severity, hostname, doc_id[:12],
            )

            # --- Step 1: Query production ES for correlated events ---
            corr = query_correlated_events(
                prod_es, anomaly, CORRELATION_WINDOW_SEC, MAX_CORRELATED_EVENTS,
            )

            # Format correlated events for the prompt (limit to avoid token overflow)
            if corr["events"]:
                events_text = "\n".join(corr["events"][:50])  # max 50 events in prompt
                if len(corr["events"]) > 50:
                    events_text += f"\n... and {len(corr['events']) - 50} more events"
            else:
                events_text = "(No correlated events found in production ES)"

            # --- Step 2: Build enriched prompt ---
            prompt = L3_PROMPT_TEMPLATE.format(
                log_line=anomaly.get("original_log_line", anomaly.get("raw", "")),
                hostname=hostname,
                process=anomaly.get("process", "unknown"),
                l2_threat_category=l2_category,
                l2_severity=l2_severity,
                l2_explanation=anomaly.get("llm_explanation", ""),
                anomaly_score=anomaly.get("anomaly_score", 0),
                window_sec=CORRELATION_WINDOW_SEC,
                correlated_events=events_text,
                correlated_count=len(corr["events"]),
                failed_auth_count=corr["failed_auth_count"],
                success_auth_count=corr["success_auth_count"],
                unique_ips=", ".join(corr["unique_ips"]) or "none found",
                unique_hosts=", ".join(corr["unique_hosts"]) or "none found",
            )

            # --- Step 3: Send to LLM for final assessment ---
            t0 = time.time()
            llm_result = query_llm(prompt)
            latency_ms = (time.time() - t0) * 1000

            # --- Step 4: Index to logs-threats (even if LLM failed) ---
            if llm_result:
                is_confirmed = llm_result.get("confirmed", False)
                # Coerce confidence_pct to int (LLM might return string or float)
                try:
                    confidence = int(llm_result.get("confidence_pct", 0))
                except (ValueError, TypeError):
                    confidence = 0
                threat_doc = {
                    "@timestamp": datetime.datetime.utcnow().isoformat() + "Z",
                    "original_anomaly_id": doc_id,
                    "original_log_line": anomaly.get("original_log_line", anomaly.get("raw", "")),
                    "hostname": hostname,
                    "process": anomaly.get("process", ""),
                    "source_ips": corr["unique_ips"],
                    "l2_threat_category": l2_category,
                    "l2_severity": l2_severity,
                    "l2_explanation": anomaly.get("llm_explanation", ""),
                    "anomaly_score": anomaly.get("anomaly_score", 0),
                    "confirmed": is_confirmed,
                    "attack_type": llm_result.get("attack_type", "unknown"),
                    "narrative": llm_result.get("narrative", ""),
                    "immediate_actions": json.dumps(llm_result.get("immediate_actions", [])),
                    "confidence_pct": confidence,
                    "severity": llm_result.get("severity", "unknown"),
                    "evidence_summary": llm_result.get("evidence_summary", ""),
                    "correlated_events_count": len(corr["events"]),
                    "failed_auth_count": corr["failed_auth_count"],
                    "success_auth_count": corr["success_auth_count"],
                    "correlation_window_sec": CORRELATION_WINDOW_SEC,
                    "l3_raw_response": json.dumps(llm_result),
                }
            else:
                # LLM failed - still index so we have visibility in the dashboard
                is_confirmed = False
                log.warning("Layer 3 LLM returned no result for doc %s - indexing as llm_failed", doc_id[:12])
                threat_doc = {
                    "@timestamp": datetime.datetime.utcnow().isoformat() + "Z",
                    "original_anomaly_id": doc_id,
                    "original_log_line": anomaly.get("original_log_line", anomaly.get("raw", "")),
                    "hostname": hostname,
                    "process": anomaly.get("process", ""),
                    "source_ips": corr["unique_ips"],
                    "l2_threat_category": l2_category,
                    "l2_severity": l2_severity,
                    "l2_explanation": anomaly.get("llm_explanation", ""),
                    "anomaly_score": anomaly.get("anomaly_score", 0),
                    "confirmed": False,
                    "attack_type": "llm_failed",
                    "narrative": "Layer 3 LLM analysis failed - event needs manual review",
                    "immediate_actions": "[]",
                    "confidence_pct": 0,
                    "severity": l2_severity,
                    "evidence_summary": f"L2 flagged as {l2_category}/{l2_severity}. L3 LLM could not analyze. Correlated events: {len(corr['events'])}",
                    "correlated_events_count": len(corr["events"]),
                    "failed_auth_count": corr["failed_auth_count"],
                    "success_auth_count": corr["success_auth_count"],
                    "correlation_window_sec": CORRELATION_WINDOW_SEC,
                    "l3_raw_response": "",
                }

            if is_confirmed:
                total_confirmed += 1

            try:
                os_client.index(index=IDX_THREATS, body=threat_doc)
            except Exception as e:
                log.warning("Failed to index threat doc: %s", e)

            # --- Step 5: Update the original anomaly doc with Layer 3 status ---
            try:
                os_client.update(
                    index="logs-anomalies",
                    id=doc_id,
                    body={
                        "doc": {
                            "l3_analyzed": True,
                            "l3_confirmed": is_confirmed,
                            "l3_attack_type": llm_result.get("attack_type", "unknown"),
                            "l3_severity": llm_result.get("severity", "unknown"),
                            "l3_confidence_pct": llm_result.get("confidence_pct", 0),
                        }
                    },
                )
            except Exception as e:
                log.warning("Failed to update anomaly doc %s with L3 results: %s", doc_id[:12], e)

            status = "CONFIRMED" if is_confirmed else "NOT CONFIRMED"
            log.info(
                "[L3] %s [%s] confidence=%d%% | %s | %s (%.0fms)",
                status,
                llm_result.get("attack_type", "?"),
                llm_result.get("confidence_pct", 0),
                hostname,
                llm_result.get("evidence_summary", "")[:80],
                latency_ms,
            )

            if total_processed % 10 == 0:
                log.info(
                    "L3 STATS | processed=%d confirmed=%d rate=%.1f%%",
                    total_processed, total_confirmed,
                    (total_confirmed / total_processed * 100) if total_processed > 0 else 0,
                )

        except redispy.ConnectionError as e:
            log.warning("Redis connection lost: %s. Reconnecting...", e)
            time.sleep(5)
            try:
                r = redispy.Redis.from_url(REDIS_HOST, decode_responses=True)
                r.ping()
            except Exception:
                pass
        except Exception as e:
            log.error("Unexpected error: %s", e, exc_info=True)
            time.sleep(1)

    log.info("Layer 3 shutdown. Processed %d events, %d confirmed threats.", total_processed, total_confirmed)


if __name__ == "__main__":
    main()
