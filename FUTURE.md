# Future Improvements

Deferred features and ideas for future implementation phases.

## Watchlist / Elevated Monitoring After Breach

When Layer 3 confirms a breach (e.g., brute force with successful login),
all subsequent events from that source IP / user / host should be monitored
with heightened alertness for a configurable period.

### Implementation Plan

**Redis watchlist with TTL:**

When Layer 3 confirms a threat, write a watchlist entry:
```python
# In layer3-engine/engine.py, after confirmed threat:
redis.setex(f"watchlist:{source_ip}:{hostname}:{username}", WATCHLIST_TTL_SEC, json.dumps({
    "reason": "brute_force_success",
    "confirmed_at": timestamp,
    "original_threat_id": threat_doc_id,
}))
```

**Layer 1 check before scoring:**
```python
# In ai-service/main.py, before Isolation Forest scoring:
watchlist_key = f"watchlist:{source_ip}:{hostname}:{username}"
if redis_client.exists(watchlist_key):
    score, is_anomaly = -1.0, True  # force-flag everything from this actor
    # Also tag the event so Layer 2 knows it's watchlisted
    doc["watchlisted"] = True
    doc["watchlist_reason"] = json.loads(redis_client.get(watchlist_key))["reason"]
```

**Configuration:**
```
WATCHLIST_TTL_SEC=3600       # 1 hour elevated monitoring
WATCHLIST_ENABLED=true
```

**Dashboard additions:**
- "Active Watchlist Entries" metric
- "Watchlisted Events" detail table

**Effort:** ~50 lines of code across engine.py and main.py.

---

## Source-Type Pipelines (Phase 3)

Per-source-type Drain3 models and Isolation Forest instances. Each source
type (database, kubernetes, hypervisor, OS syslog) gets its own:
- Drain3 template miner (specialized patterns)
- Isolation Forest model (source-specific baseline)
- Suspicious pattern regexes
- Anomaly threshold
- Template allowlist

### Implementation Plan

**YAML config files per source type:**
```yaml
# templates/database.yml
pipeline: database
source_topics:
  - logs-database
drain3:
  sim_th: 0.5
  max_clusters: 256
isolation_forest:
  threshold: -0.5
  contamination: auto
  training_window: 10000
suspicious_patterns:
  - pattern: "deadlock detected"
    category: "db_deadlock"
    score: 0.9
allowlist_patterns:
  - "checkpoint complete"
  - "automatic vacuum"
```

**Kafka consumer integration:**
Replace Redis input with direct Kafka topic consumption. Each ai-service
instance subscribes to specific topics based on its pipeline config.

**Effort:** Large - new config loader, pipeline router, multi-model management.

---

## Template Rules (Manual Allowlist/Blocklist)

YAML-based rules to manually mark templates as always-normal or
always-suspicious, independent of the automatic allowlist.

```yaml
# templates/rules.yml
allowlist:
  - "pam_unix(cron:session): session * for user *"
  - "Started Session * of User *"
blocklist:
  - "Failed password for * from *"
  - "FAILED SU (to root) *"
  - "Out of memory: Killed process *"
```

**Effort:** Medium - YAML loader + pattern matching against Drain3 templates.

---

## MCP Integration for Agentic ES Queries

Let the Layer 3 LLM dynamically decide what to query from Elasticsearch
instead of using predefined correlation queries. The LLM would use MCP
tool calls to search ES, analyze results, and potentially run follow-up
queries.

Useful for complex attack patterns that don't fit predefined query templates.

**Prerequisites:** MCP server running, GPU for larger model (agentic
tool calling on small models is unreliable).

**Effort:** Large - MCP client integration, prompt engineering for tool use,
error handling for bad queries.

---

## Horizontal Scaling of Layer 1

Run multiple ai-service instances consuming from the same Redis queue.
Redis BLPOP is atomic - each message consumed by exactly one instance.

```yaml
# docker-compose.yml
ai-service:
  deploy:
    replicas: 8
```

Each instance maintains its own Isolation Forest model. With enough volume
(>1000 events/sec), each instance sees a representative sample within
minutes of startup.

**Effort:** Zero code changes - just configuration. Test with 2 replicas first.

---

## Rate-Based Pre-Filter

Skip Isolation Forest scoring for high-frequency templates entirely.
If a template appears more than N times per minute, it's noise by definition.

Track template rate in a sliding window (e.g., last 60 seconds). Only score
events from templates with fewer than the threshold occurrences.

**Effort:** Medium - sliding window counter per template, configurable threshold.

---

## Per-Host Baseline Models

Instead of one global Isolation Forest, maintain separate models per hostname.
"Failed password" from a bastion host is normal, from a database server is
suspicious.

**Challenge:** Memory usage scales with number of hosts (8000 hosts = 8000 models).
Could use model sharing for hosts with similar log profiles.

**Effort:** Large - model management, memory optimization, host grouping logic.
