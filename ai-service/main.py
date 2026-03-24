#!/usr/bin/env python3
"""
AI Log Filter PoC - Single-script log analysis service.

Reads syslog files, parses log templates with Drain3, detects anomalies
with Isolation Forest, and optionally enriches flagged events with a
local LLM via Ollama. Results are indexed into OpenSearch.
"""

import os
import re
import sys
import json
import time
import signal
import logging
import hashlib
import datetime
from collections import defaultdict, deque
from threading import Thread, Event

import numpy as np
from sklearn.ensemble import IsolationForest
from sklearn.preprocessing import StandardScaler
from opensearchpy import OpenSearch, helpers as os_helpers
from drain3 import TemplateMiner
from drain3.template_miner_config import TemplateMinerConfig
import requests

# ---------------------------------------------------------------------------
# Configuration (all from environment, with sane defaults)
# ---------------------------------------------------------------------------
OPENSEARCH_HOST = os.getenv("OPENSEARCH_HOST", "http://localhost:9200")
OLLAMA_HOST = os.getenv("OLLAMA_HOST", "http://localhost:11434")
LOG_FILE = os.getenv("LOG_FILE", "/var/log/syslog")
LLM_MODEL = os.getenv("LLM_MODEL", "qwen2.5:3b")
LLM_ENABLED = os.getenv("LLM_ENABLED", "true").lower() == "true"
ANOMALY_THRESHOLD = float(os.getenv("ANOMALY_THRESHOLD", "-0.15"))
TRAINING_WINDOW = int(os.getenv("TRAINING_WINDOW", "500"))
BATCH_SIZE = int(os.getenv("BATCH_SIZE", "50"))

# How many seconds worth of logs to aggregate into a feature window
FEATURE_WINDOW_SEC = int(os.getenv("FEATURE_WINDOW_SEC", "60"))

# Indices
IDX_PROCESSED = "logs-processed"
IDX_ANOMALIES = "logs-anomalies"
IDX_STATS = "logs-stats"

# ---------------------------------------------------------------------------
# Logging
# ---------------------------------------------------------------------------
logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s [%(levelname)s] %(message)s",
    stream=sys.stdout,
)
log = logging.getLogger("ai-log-filter")

# Graceful shutdown
shutdown_event = Event()


def _handle_signal(signum, frame):
    log.info("Received signal %s, shutting down ...", signum)
    shutdown_event.set()


signal.signal(signal.SIGINT, _handle_signal)
signal.signal(signal.SIGTERM, _handle_signal)

# ---------------------------------------------------------------------------
# Syslog parser (regex-based, works for standard RFC 3164 syslog)
# ---------------------------------------------------------------------------
# Example: "Mar 24 10:15:32 myhost sshd[12345]: Failed password for root from 10.0.0.1 port 22 ssh2"
SYSLOG_RE = re.compile(
    r"^(?P<timestamp>\w{3}\s+\d{1,2}\s+\d{2}:\d{2}:\d{2})\s+"
    r"(?P<hostname>\S+)\s+"
    r"(?P<process>\S+?)(?:\[(?P<pid>\d+)\])?:\s+"
    r"(?P<message>.+)$"
)

# Severity keywords
SEVERITY_KEYWORDS = {
    "emerg": 0, "alert": 1, "crit": 2, "error": 3, "err": 3,
    "warning": 4, "warn": 4, "notice": 5, "info": 6, "debug": 7,
}

# Suspicious patterns for quick heuristic scoring
SUSPICIOUS_PATTERNS = [
    (re.compile(r"failed password", re.I), "auth_failure", 0.7),
    (re.compile(r"authentication fail", re.I), "auth_failure", 0.7),
    (re.compile(r"invalid user", re.I), "auth_failure", 0.6),
    (re.compile(r"refused connect", re.I), "network_issue", 0.5),
    (re.compile(r"connection reset", re.I), "network_issue", 0.4),
    (re.compile(r"out of memory", re.I), "resource_exhaustion", 0.9),
    (re.compile(r"oom-killer", re.I), "resource_exhaustion", 0.95),
    (re.compile(r"segfault", re.I), "crash", 0.8),
    (re.compile(r"kernel panic", re.I), "crash", 1.0),
    (re.compile(r"permission denied", re.I), "access_denied", 0.5),
    (re.compile(r"unauthorized", re.I), "access_denied", 0.6),
    (re.compile(r"disk full", re.I), "resource_exhaustion", 0.8),
    (re.compile(r"no space left", re.I), "resource_exhaustion", 0.8),
    (re.compile(r"sudo:.*COMMAND=", re.I), "privilege_escalation", 0.3),
    (re.compile(r"accepted publickey|accepted password", re.I), "successful_login", 0.1),
]


def parse_syslog_line(line: str) -> dict | None:
    """Parse a single syslog line into a structured dict."""
    line = line.strip()
    if not line:
        return None
    m = SYSLOG_RE.match(line)
    if not m:
        # Fallback: store raw line
        return {
            "raw": line,
            "timestamp_str": "",
            "hostname": "unknown",
            "process": "unknown",
            "pid": None,
            "message": line,
        }
    return {
        "raw": line,
        "timestamp_str": m.group("timestamp"),
        "hostname": m.group("hostname"),
        "process": m.group("process"),
        "pid": m.group("pid"),
        "message": m.group("message"),
    }


def detect_severity(message: str) -> tuple[str, int]:
    """Detect log severity from message content."""
    msg_lower = message.lower()
    for keyword, level in sorted(SEVERITY_KEYWORDS.items(), key=lambda x: x[1]):
        if keyword in msg_lower:
            return keyword, level
    return "info", 6


def detect_suspicious_patterns(message: str) -> list[dict]:
    """Check message against known suspicious patterns."""
    hits = []
    for pattern, category, score in SUSPICIOUS_PATTERNS:
        if pattern.search(message):
            hits.append({"category": category, "score": score})
    return hits


# ---------------------------------------------------------------------------
# Drain3 log template miner
# ---------------------------------------------------------------------------
def create_template_miner() -> TemplateMiner:
    """Create a Drain3 template miner with sensible defaults."""
    config = TemplateMinerConfig()
    config.drain_sim_th = 0.4
    config.drain_depth = 4
    config.drain_max_children = 100
    config.drain_max_clusters = 1024
    return TemplateMiner(config=config)


# ---------------------------------------------------------------------------
# Feature engineering for Isolation Forest
# ---------------------------------------------------------------------------
class FeatureExtractor:
    """
    Extracts numeric features from parsed log events for anomaly detection.

    Features per event:
    1. message_length        - length of log message
    2. severity_level        - numeric severity (0=emerg .. 7=debug)
    3. suspicious_score      - max score from pattern matching
    4. template_id           - hash of the Drain3 template (numeric)
    5. template_frequency    - how often we've seen this template recently
    6. hour_of_day           - 0-23
    7. process_frequency     - how often this process appears recently
    8. is_new_template       - 1 if template was never seen before
    """

    def __init__(self, template_miner: TemplateMiner):
        self.miner = template_miner
        self.template_counts = defaultdict(int)
        self.process_counts = defaultdict(int)
        self.seen_templates = set()
        self.total_events = 0

    def extract(self, parsed: dict) -> tuple[np.ndarray, dict]:
        """Return (feature_vector, metadata_dict) for one parsed log event."""
        msg = parsed["message"]
        self.total_events += 1

        # Drain3 template
        result = self.miner.add_log_message(msg)
        template_id = result.cluster_id if result else 0
        template_str = result.get_template() if result else msg

        # Template frequency
        self.template_counts[template_id] += 1
        template_freq = self.template_counts[template_id]

        # New template?
        is_new = 1 if template_id not in self.seen_templates else 0
        self.seen_templates.add(template_id)

        # Process frequency
        proc = parsed.get("process", "unknown")
        self.process_counts[proc] += 1
        proc_freq = self.process_counts[proc]

        # Severity
        severity_name, severity_level = detect_severity(msg)

        # Suspicious patterns
        suspicious = detect_suspicious_patterns(msg)
        max_suspicious_score = max((h["score"] for h in suspicious), default=0.0)
        suspicious_categories = [h["category"] for h in suspicious]

        # Hour of day (parse from timestamp or use current)
        hour = _parse_hour(parsed.get("timestamp_str", ""))

        # Numeric template_id hash (make it a bounded int)
        tid_hash = int(hashlib.md5(str(template_id).encode()).hexdigest()[:8], 16) % 10000

        features = np.array([
            len(msg),                     # message_length
            severity_level,               # severity_level
            max_suspicious_score,         # suspicious_score
            tid_hash,                     # template_id_hash
            template_freq,                # template_frequency
            hour,                         # hour_of_day
            proc_freq,                    # process_frequency
            is_new,                       # is_new_template
        ], dtype=np.float64)

        metadata = {
            "template_id": template_id,
            "template_str": template_str,
            "severity": severity_name,
            "severity_level": severity_level,
            "suspicious_score": max_suspicious_score,
            "suspicious_categories": suspicious_categories,
            "is_new_template": bool(is_new),
        }

        return features, metadata


def _parse_hour(ts_str: str) -> int:
    """Extract hour from syslog timestamp like 'Mar 24 10:15:32'."""
    try:
        parts = ts_str.strip().split()
        if len(parts) >= 3:
            time_part = parts[2]
            return int(time_part.split(":")[0])
    except (IndexError, ValueError):
        pass
    return datetime.datetime.now().hour


# ---------------------------------------------------------------------------
# Anomaly detector (Isolation Forest with online retraining)
# ---------------------------------------------------------------------------
class AnomalyDetector:
    """Wraps Isolation Forest with periodic retraining."""

    def __init__(self, training_window: int = 500, threshold: float = -0.15):
        self.training_window = training_window
        self.threshold = threshold
        self.buffer = deque(maxlen=training_window * 2)
        self.model: IsolationForest | None = None
        self.scaler = StandardScaler()
        self.is_trained = False
        self.events_since_retrain = 0
        self.retrain_interval = training_window  # retrain every N events

    def add_and_score(self, features: np.ndarray) -> tuple[float, bool]:
        """
        Add features to buffer, return (anomaly_score, is_anomaly).
        Score from sklearn: negative = more anomalous, positive = normal.
        """
        self.buffer.append(features)
        self.events_since_retrain += 1

        # Train if we have enough data
        if not self.is_trained and len(self.buffer) >= self.training_window:
            self._train()
        elif self.is_trained and self.events_since_retrain >= self.retrain_interval:
            self._train()

        if not self.is_trained:
            # During warmup, use heuristic: suspicious_score > 0.5 is anomaly
            suspicious_score = features[2]
            return -suspicious_score, suspicious_score > 0.3

        # Score the event
        X = self.scaler.transform(features.reshape(1, -1))
        score = self.model.score_samples(X)[0]
        is_anomaly = score < self.threshold
        return score, is_anomaly

    def _train(self):
        """Retrain the model on the current buffer."""
        X = np.array(list(self.buffer))
        self.scaler.fit(X)
        X_scaled = self.scaler.transform(X)

        self.model = IsolationForest(
            n_estimators=200,
            contamination=0.05,  # expect ~5% anomalies
            random_state=42,
            n_jobs=-1,
        )
        self.model.fit(X_scaled)
        self.is_trained = True
        self.events_since_retrain = 0
        log.info(
            "Isolation Forest retrained on %d samples (buffer size: %d)",
            len(X), len(self.buffer),
        )


# ---------------------------------------------------------------------------
# Ollama LLM integration
# ---------------------------------------------------------------------------
LLM_PROMPT_TEMPLATE = """You are a security analyst reviewing syslog entries flagged as anomalous.
Analyze the following log entry and provide a brief assessment.

Log entry:
{log_line}

Context:
- Source host: {hostname}
- Process: {process}
- Detected anomaly score: {score:.3f}
- Pattern matches: {patterns}
- Log template: {template}

Respond in this exact JSON format (no markdown, no extra text):
{{"threat_category": "<one of: brute_force, privilege_escalation, service_failure, resource_exhaustion, network_anomaly, configuration_error, data_exfiltration, benign_anomaly, unknown>", "severity": "<one of: critical, high, medium, low, info>", "explanation": "<1-2 sentence explanation>", "recommended_action": "<1 sentence recommendation>"}}"""


def query_ollama(prompt: str, model: str = LLM_MODEL) -> dict | None:
    """Send a prompt to Ollama and parse the JSON response."""
    try:
        resp = requests.post(
            f"{OLLAMA_HOST}/api/generate",
            json={
                "model": model,
                "prompt": prompt,
                "stream": False,
                "options": {
                    "temperature": 0.1,
                    "num_predict": 256,
                },
            },
            timeout=120,
        )
        resp.raise_for_status()
        text = resp.json().get("response", "")

        # Try to extract JSON from the response
        # Sometimes LLMs wrap in ```json ... ```
        text = text.strip()
        if text.startswith("```"):
            text = re.sub(r"^```(?:json)?\s*", "", text)
            text = re.sub(r"\s*```$", "", text)

        return json.loads(text)
    except requests.exceptions.ConnectionError:
        log.warning("Ollama not reachable at %s", OLLAMA_HOST)
        return None
    except (json.JSONDecodeError, KeyError) as e:
        log.warning("Failed to parse LLM response: %s (response: %.200s)", e, text)
        return None
    except Exception as e:
        log.warning("Ollama query failed: %s", e)
        return None


def ensure_ollama_model(model: str = LLM_MODEL):
    """Pull the model if not already present in Ollama."""
    log.info("Ensuring Ollama model '%s' is available ...", model)
    for attempt in range(30):
        try:
            # Check if model exists
            resp = requests.get(f"{OLLAMA_HOST}/api/tags", timeout=10)
            if resp.ok:
                models = [m["name"] for m in resp.json().get("models", [])]
                # Check exact match or match without tag
                if any(model in m or m.startswith(model) for m in models):
                    log.info("Model '%s' already available.", model)
                    return True

                # Pull it
                log.info("Pulling model '%s' (this may take a while on first run)...", model)
                pull_resp = requests.post(
                    f"{OLLAMA_HOST}/api/pull",
                    json={"name": model, "stream": False},
                    timeout=1800,  # 30 min for large model download
                )
                if pull_resp.ok:
                    log.info("Model '%s' pulled successfully.", model)
                    return True
                else:
                    log.warning("Pull failed: %s", pull_resp.text[:200])
        except requests.exceptions.ConnectionError:
            log.info("Waiting for Ollama to be ready (attempt %d/30)...", attempt + 1)
            time.sleep(10)
        except Exception as e:
            log.warning("Error checking Ollama: %s", e)
            time.sleep(5)

    log.error("Could not ensure Ollama model after 30 attempts. LLM analysis disabled.")
    return False


# ---------------------------------------------------------------------------
# OpenSearch integration
# ---------------------------------------------------------------------------
def create_opensearch_client() -> OpenSearch:
    """Create and return an OpenSearch client."""
    # Parse host from URL
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
            info = client.info()
            log.info("OpenSearch ready: %s", info.get("version", {}).get("number", "unknown"))
            return True
        except Exception:
            log.info("Waiting for OpenSearch (attempt %d/%d)...", i + 1, max_retries)
            time.sleep(5)
    log.error("OpenSearch not available after %d retries.", max_retries)
    return False


def setup_indices(client: OpenSearch):
    """Create index templates and indices."""
    # Common mapping for processed logs
    processed_mapping = {
        "mappings": {
            "properties": {
                "@timestamp": {"type": "date"},
                "raw": {"type": "text"},
                "hostname": {"type": "keyword"},
                "process": {"type": "keyword"},
                "pid": {"type": "keyword"},
                "message": {"type": "text", "fields": {"keyword": {"type": "keyword", "ignore_above": 512}}},
                "severity": {"type": "keyword"},
                "severity_level": {"type": "integer"},
                "anomaly_score": {"type": "float"},
                "is_anomaly": {"type": "boolean"},
                "suspicious_score": {"type": "float"},
                "suspicious_categories": {"type": "keyword"},
                "template_id": {"type": "integer"},
                "template_str": {"type": "keyword"},
                "is_new_template": {"type": "boolean"},
                "model_trained": {"type": "boolean"},
            }
        },
        "settings": {
            "number_of_shards": 1,
            "number_of_replicas": 0,
        }
    }

    # Anomalies index has extra LLM fields
    anomaly_mapping = {
        "mappings": {
            "properties": {
                **processed_mapping["mappings"]["properties"],
                "llm_threat_category": {"type": "keyword"},
                "llm_severity": {"type": "keyword"},
                "llm_explanation": {"type": "text"},
                "llm_recommended_action": {"type": "text"},
                "llm_raw_response": {"type": "text"},
                "llm_analyzed": {"type": "boolean"},
            }
        },
        "settings": processed_mapping["settings"],
    }

    # Stats index
    stats_mapping = {
        "mappings": {
            "properties": {
                "@timestamp": {"type": "date"},
                "events_total": {"type": "long"},
                "events_anomalous": {"type": "long"},
                "anomaly_rate_pct": {"type": "float"},
                "events_per_sec": {"type": "float"},
                "model_trained": {"type": "boolean"},
                "buffer_size": {"type": "integer"},
                "unique_templates": {"type": "integer"},
                "llm_queries": {"type": "long"},
                "llm_avg_latency_ms": {"type": "float"},
            }
        },
        "settings": {
            "number_of_shards": 1,
            "number_of_replicas": 0,
        }
    }

    for idx, mapping in [(IDX_PROCESSED, processed_mapping),
                          (IDX_ANOMALIES, anomaly_mapping),
                          (IDX_STATS, stats_mapping)]:
        try:
            if not client.indices.exists(index=idx):
                client.indices.create(index=idx, body=mapping)
                log.info("Created index: %s", idx)
            else:
                log.info("Index already exists: %s", idx)
        except Exception as e:
            log.warning("Failed to create index %s: %s", idx, e)


# ---------------------------------------------------------------------------
# Stats tracker
# ---------------------------------------------------------------------------
class StatsTracker:
    """Track and periodically flush processing statistics."""

    def __init__(self, client: OpenSearch, flush_interval: int = 30):
        self.client = client
        self.flush_interval = flush_interval
        self.total = 0
        self.anomalous = 0
        self.llm_queries = 0
        self.llm_total_latency = 0.0
        self.last_flush = time.time()
        self.last_total = 0

    def record_event(self, is_anomaly: bool):
        self.total += 1
        if is_anomaly:
            self.anomalous += 1

    def record_llm_query(self, latency_ms: float):
        self.llm_queries += 1
        self.llm_total_latency += latency_ms

    def maybe_flush(self, model_trained: bool, buffer_size: int, unique_templates: int):
        now = time.time()
        elapsed = now - self.last_flush
        if elapsed < self.flush_interval:
            return

        events_in_period = self.total - self.last_total
        eps = events_in_period / elapsed if elapsed > 0 else 0
        anomaly_rate = (self.anomalous / self.total * 100) if self.total > 0 else 0
        avg_llm_latency = (self.llm_total_latency / self.llm_queries) if self.llm_queries > 0 else 0

        doc = {
            "@timestamp": datetime.datetime.utcnow().isoformat() + "Z",
            "events_total": self.total,
            "events_anomalous": self.anomalous,
            "anomaly_rate_pct": round(anomaly_rate, 2),
            "events_per_sec": round(eps, 2),
            "model_trained": model_trained,
            "buffer_size": buffer_size,
            "unique_templates": unique_templates,
            "llm_queries": self.llm_queries,
            "llm_avg_latency_ms": round(avg_llm_latency, 1),
        }

        try:
            self.client.index(index=IDX_STATS, body=doc)
        except Exception as e:
            log.warning("Failed to flush stats: %s", e)

        self.last_flush = now
        self.last_total = self.total

        log.info(
            "STATS | total=%d anomalies=%d rate=%.1f%% eps=%.1f templates=%d llm_queries=%d",
            self.total, self.anomalous, anomaly_rate, eps, unique_templates, self.llm_queries,
        )


# ---------------------------------------------------------------------------
# File tailer (similar to tail -F)
# ---------------------------------------------------------------------------
def tail_file(filepath: str, shutdown: Event):
    """Generator that yields new lines from a file, similar to tail -F."""
    log.info("Tailing file: %s", filepath)

    # Wait for file to exist
    while not os.path.exists(filepath) and not shutdown.is_set():
        log.info("Waiting for log file %s to appear...", filepath)
        time.sleep(2)

    if shutdown.is_set():
        return

    with open(filepath, "r") as f:
        # Start from the end of the file
        f.seek(0, 2)

        while not shutdown.is_set():
            line = f.readline()
            if line:
                yield line
            else:
                time.sleep(0.1)


# ---------------------------------------------------------------------------
# Main processing loop
# ---------------------------------------------------------------------------
def main():
    log.info("=" * 60)
    log.info("AI Log Filter PoC - Starting up")
    log.info("=" * 60)
    log.info("Config: OPENSEARCH_HOST=%s", OPENSEARCH_HOST)
    log.info("Config: OLLAMA_HOST=%s", OLLAMA_HOST)
    log.info("Config: LOG_FILE=%s", LOG_FILE)
    log.info("Config: LLM_MODEL=%s", LLM_MODEL)
    log.info("Config: LLM_ENABLED=%s", LLM_ENABLED)
    log.info("Config: ANOMALY_THRESHOLD=%s", ANOMALY_THRESHOLD)
    log.info("Config: TRAINING_WINDOW=%s", TRAINING_WINDOW)

    # --- Initialize components ---
    os_client = create_opensearch_client()
    if not wait_for_opensearch(os_client):
        sys.exit(1)

    setup_indices(os_client)

    # Ollama model
    llm_available = False
    if LLM_ENABLED:
        llm_available = ensure_ollama_model(LLM_MODEL)
        if not llm_available:
            log.warning("LLM not available, continuing with ML-only analysis.")

    # ML components
    template_miner = create_template_miner()
    feature_extractor = FeatureExtractor(template_miner)
    anomaly_detector = AnomalyDetector(
        training_window=TRAINING_WINDOW,
        threshold=ANOMALY_THRESHOLD,
    )
    stats = StatsTracker(os_client)

    # Bulk indexing buffer
    bulk_buffer = []

    log.info("Initialization complete. Starting log processing ...")

    # --- Main loop ---
    for line in tail_file(LOG_FILE, shutdown_event):
        if shutdown_event.is_set():
            break

        # Parse
        parsed = parse_syslog_line(line)
        if parsed is None:
            continue

        # Extract features
        features, metadata = feature_extractor.extract(parsed)

        # Anomaly detection
        score, is_anomaly = anomaly_detector.add_and_score(features)

        # Build the base document
        now_iso = datetime.datetime.utcnow().isoformat() + "Z"
        doc = {
            "@timestamp": now_iso,
            "raw": parsed["raw"],
            "hostname": parsed["hostname"],
            "process": parsed["process"],
            "pid": parsed.get("pid"),
            "message": parsed["message"],
            "severity": metadata["severity"],
            "severity_level": metadata["severity_level"],
            "anomaly_score": round(float(score), 4),
            "is_anomaly": is_anomaly,
            "suspicious_score": metadata["suspicious_score"],
            "suspicious_categories": metadata["suspicious_categories"],
            "template_id": metadata["template_id"],
            "template_str": metadata["template_str"],
            "is_new_template": metadata["is_new_template"],
            "model_trained": anomaly_detector.is_trained,
        }

        # Add to bulk buffer for processed index
        bulk_buffer.append({
            "_index": IDX_PROCESSED,
            "_source": doc,
        })

        # If anomaly, optionally run through LLM and index to anomalies index
        if is_anomaly:
            anomaly_doc = dict(doc)
            anomaly_doc["llm_analyzed"] = False

            if llm_available and LLM_ENABLED:
                prompt = LLM_PROMPT_TEMPLATE.format(
                    log_line=parsed["raw"],
                    hostname=parsed["hostname"],
                    process=parsed["process"],
                    score=score,
                    patterns=", ".join(metadata["suspicious_categories"]) or "none",
                    template=metadata["template_str"],
                )

                t0 = time.time()
                llm_result = query_ollama(prompt)
                latency_ms = (time.time() - t0) * 1000
                stats.record_llm_query(latency_ms)

                if llm_result:
                    anomaly_doc["llm_analyzed"] = True
                    anomaly_doc["llm_threat_category"] = llm_result.get("threat_category", "unknown")
                    anomaly_doc["llm_severity"] = llm_result.get("severity", "unknown")
                    anomaly_doc["llm_explanation"] = llm_result.get("explanation", "")
                    anomaly_doc["llm_recommended_action"] = llm_result.get("recommended_action", "")
                    anomaly_doc["llm_raw_response"] = json.dumps(llm_result)

                    log.info(
                        "ANOMALY [%s/%s] %s | %s",
                        llm_result.get("threat_category", "?"),
                        llm_result.get("severity", "?"),
                        parsed["raw"][:120],
                        llm_result.get("explanation", "")[:100],
                    )
                else:
                    log.info("ANOMALY [score=%.3f] %s", score, parsed["raw"][:120])
            else:
                log.info("ANOMALY [score=%.3f] %s", score, parsed["raw"][:120])

            bulk_buffer.append({
                "_index": IDX_ANOMALIES,
                "_source": anomaly_doc,
            })

        # Track stats
        stats.record_event(is_anomaly)

        # Flush bulk buffer
        if len(bulk_buffer) >= BATCH_SIZE:
            _flush_bulk(os_client, bulk_buffer)
            bulk_buffer.clear()

        # Flush stats periodically
        stats.maybe_flush(
            model_trained=anomaly_detector.is_trained,
            buffer_size=len(anomaly_detector.buffer),
            unique_templates=len(feature_extractor.seen_templates),
        )

    # Final flush
    if bulk_buffer:
        _flush_bulk(os_client, bulk_buffer)

    log.info("Shutdown complete. Processed %d events total.", stats.total)


def _flush_bulk(client: OpenSearch, buffer: list):
    """Bulk index documents to OpenSearch."""
    try:
        success, errors = os_helpers.bulk(client, buffer, raise_on_error=False)
        if errors:
            log.warning("Bulk index had %d errors", len(errors) if isinstance(errors, list) else errors)
    except Exception as e:
        log.warning("Bulk index failed: %s", e)


# ---------------------------------------------------------------------------
if __name__ == "__main__":
    main()
