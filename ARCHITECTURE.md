# AI Log Filter - Architecture & How It Works

## Overview

The AI Log Filter is a CPU-based proof of concept for intelligent syslog
anomaly detection. It uses a two-layer AI approach: fast classical machine
learning for real-time scoring of every event, and a local LLM for deep
analysis of flagged anomalies only.

The system is designed to answer the question: **"Can we do useful AI-powered
log analysis on CPU-only hardware before investing in GPU infrastructure?"**

---

## System Architecture

```
                    DATA SOURCES                          DOCKER STACK
                    ────────────                          ────────────

                                                    ┌─────────────────┐
  syslog-ng ──TCP/UDP:5514──────────────────────>   │ syslog-receiver  │
  (remote servers)                                  │ (Python socket   │
                                                    │  server)         │
                                                    └────────┬────────┘
                                                             │ RPUSH
  Filebeat ──────────────────────────────────────>           │
  (host, optional)                                           ▼
                                                    ┌─────────────────┐
  inject-anomalies.sh ──> /var/log/messages         │     Redis        │
  (testing)               ──> syslog-ng ──────>     │  (in-memory      │
                                                    │   buffer, list)  │
                                                    └────────┬────────┘
                                                             │ BLPOP
              ┌──────────────────────────────────────────────┘
              ▼
    ┌───────────────────────────────────────────────────────────────┐
    │                    AI SERVICE (main.py)                        │
    │                                                               │
    │   Main Thread                          LLM Worker Thread(s)   │
    │   ───────────                          ────────────────────   │
    │                                                               │
    │   Redis BLPOP ──> Parse ──> Extract    Queue ──> Ollama API   │
    │                   syslog    features        ──> Update doc    │
    │                      │         │               in OpenSearch   │
    │                      │         ▼                               │
    │                      │   Isolation Forest                      │
    │                      │   score + flag                          │
    │                      │         │                               │
    │                      │    ┌────┴────┐                         │
    │                      │    │         │                          │
    │                      │  normal   anomaly                      │
    │                      │    │         │                          │
    │                      │    │    ┌────┴────────┐                │
    │                      │    │    │ Index with  │                │
    │                      │    │    │ llm_analyzed│                │
    │                      │    │    │ = false     │                │
    │                      │    │    │             │                │
    │                      │    │    │ Submit to   │                │
    │                      │    │    │ LLM queue   │───────>  Queue │
    │                      │    │    └─────────────┘                │
    │                      │    │                                    │
    │                      ▼    ▼                                    │
    │               Bulk index to OpenSearch                         │
    │               (logs-processed)                                 │
    └───────────────────────────────────────────────────────────────┘
              │                                        │
              ▼                                        ▼
    ┌───────────────────────────────────────────────────────────────┐
    │                       OpenSearch                               │
    │                                                               │
    │   logs-processed    logs-anomalies         logs-stats          │
    │   (all events)      (flagged events,       (throughput,        │
    │                      LLM results via        anomaly rate,      │
    │                      async update)          queue depth)       │
    └───────────────────────┬───────────────────────────────────────┘
                            │
                            ▼
    ┌───────────────────────────────────────────────────────────────┐
    │                  OpenSearch Dashboards                         │
    │                                                               │
    │   TOP:    Threat Categories | Severity | Pending | Queue      │
    │   MIDDLE: LLM Analysis Detail Table                           │
    │   LOWER:  Events Over Time | Score Dist | Top Hosts           │
    │   BOTTOM: Patterns | Throughput | Anomaly Rate                │
    └───────────────────────────────────────────────────────────────┘

    ┌───────────────────────────────────────────────────────────────┐
    │                       Ollama                                   │
    │                                                               │
    │   Qwen3.5-0.8B (quantized, CPU inference)                      │
    │   ~60-120 tokens/sec on modern CPUs                            │
    │   ~2-10 seconds per event analysis                             │
    └───────────────────────────────────────────────────────────────┘
```

---

## Component Details

### 1. Syslog Receiver (`syslog-receiver/receiver.py`)

A lightweight Python socket server that accepts syslog messages and pushes
them into Redis.

**Protocols:** TCP + UDP on port 5514 (configurable)

**How it works:**
- TCP: Threaded server, one thread per connection. Handles RFC 5425
  octet-counting framing. Each newline-delimited message is pushed
  to Redis via `RPUSH`.
- UDP: Each datagram is a single syslog message. Batches messages
  into Redis pipelines for throughput (flushes every 100 messages or
  500ms, whichever comes first).
- Auto-reconnects to Redis if the connection drops.
- Logs stats every 30 seconds (total received, errors).

**Why a separate container?** Decouples network I/O from the AI processing.
The receiver can handle thousands of connections and burst traffic while
Redis absorbs backpressure.

### 2. Redis (Buffer)

Standard Redis 7 running as a pure in-memory FIFO queue.

**Configuration:**
- `maxmemory 4gb` - caps memory usage (increase if the server has ample RAM)
- `maxmemory-policy noeviction` - returns error when full rather than
  silently dropping messages
- No persistence (`appendonly no`, `save ""`) - pure speed, no disk I/O

**How data flows:**
- Syslog receiver and/or Filebeat push messages with `RPUSH filebeat:logs`
- AI service consumes with `BLPOP filebeat:logs` (blocking pop)
- Queue depth should stay near 0 during normal operation. If it grows,
  it means the AI service is processing slower than the input rate.

**Why Redis?** It provides backpressure buffering. If the AI service restarts,
crashes, or falls behind (especially during LLM analysis), messages queue
safely in RAM rather than being lost. On servers with ample RAM, you can
increase the Redis `maxmemory` to buffer millions of events.

### 3. AI Service - Main Thread (`ai-service/main.py`)

The core processing pipeline. Runs as a single main thread that processes
events sequentially, never blocking on the LLM.

#### Step 1: Input (`main.py:802-868`)

Two input modes selected by `INPUT_MODE` env var:

- **`redis` (default):** Calls `BLPOP` on the Redis list with a 1-second
  timeout. Handles both raw syslog lines and Filebeat JSON envelopes
  (`{"message": "the syslog line", ...}`). Auto-reconnects on connection
  failure.

- **`file`:** Tails a log file from the beginning (like `tail -f` but
  starting at byte 0). Used for demo mode with the synthetic generator.

#### Step 2: Syslog Parsing (`main.py:93-156`)

Regex-based parser for RFC 3164 syslog format. Extracts:

```
Input:  "<13>Mar 24 23:37:02 vcvub10223 sshd[12345]: Failed password for root ..."
         ^^^^                 ^^^^^^^^^^  ^^^^  ^^^^^  ^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^
         priority (stripped)  hostname    proc   pid   message
```

- Handles optional syslog priority prefix (`<0>` through `<191>`)
- Falls back to storing the raw line if the regex doesn't match

#### Step 3: Feature Extraction (`main.py:190-273`)

Converts each parsed log event into a numeric vector of 8 features for
the Isolation Forest model:

```
Feature Vector: [msg_len, severity, suspicious_score, template_hash,
                 template_rarity, hour_of_day, process_ratio, msg_word_count]
```

All features are bounded or naturally constrained, so the model behaves
consistently regardless of how long the service has been running.

**Feature details:**

| # | Feature | Source | Range | Rationale |
|---|---------|--------|-------|-----------|
| 1 | `message_length` | `len(message)` | 0-∞ | Anomalous events often have unusual lengths (stack traces, binary data, very long error messages) |
| 2 | `severity_level` | Keyword scan | 0-7 | Scans for keywords like "emerg", "crit", "error", "warning" in the message text. Lower number = more severe. |
| 3 | `suspicious_score` | Regex patterns | 0.0-1.0 | 15 compiled regex patterns match known suspicious content: "failed password" (0.7), "out of memory" (0.9), "segfault" (0.8), "kernel panic" (1.0), etc. Returns the max match score. This is a **heuristic booster**, not the decision maker. |
| 4 | `template_id_hash` | Drain3 + MD5 | 0-9999 | Drain3 clusters similar messages into templates (e.g., "Failed password for `<*>` from `<*>` port `<*>` ssh2"). The template ID is hashed to a bounded integer. Groups similar messages together. |
| 5 | `template_rarity` | `1 / template_count` | 0.0-1.0 | Inverse of how often this template has been seen. Rare templates (seen once = 1.0) score high, common templates (seen 1000 times = 0.001) score near zero. Better than raw frequency counts which grow unboundedly over time. |
| 6 | `hour_of_day` | Timestamp parse | 0-23 | Some events are normal at 10 AM but suspicious at 3 AM (e.g., SSH logins, batch jobs). |
| 7 | `process_ratio` | `count / total_events` | 0.0-1.0 | Normalized frequency of this process name relative to all events. A process that appears in 50% of logs vs one that appears in 0.01% provides a bounded signal. |
| 8 | `msg_word_count` | `len(msg.split())` | 0-∞ | Number of words in the message. Provides a structural dimension different from `message_length` (character count) - anomalous messages like stack traces have many words, while binary data or short alerts have few. |

**Drain3 Log Template Mining (`main.py:177-187`):**

Drain3 is a streaming log parser that automatically discovers log templates
from unstructured text. It doesn't need training data or configuration -
it learns patterns from the stream itself.

Example:
```
Input:  "Failed password for root from 185.220.101.42 port 52431 ssh2"
Input:  "Failed password for admin from 45.155.205.233 port 38102 ssh2"
Output: "Failed password for <*> from <*> port <*> ssh2"  (template_id=7)

Input:  "Started Session 4521 of User alice"
Input:  "Started Session 8832 of User bob"
Output: "Started Session <*> of User <*>"  (template_id=12)
```

The `<*>` tokens represent variable parts. Drain3 uses a fixed-depth parse
tree to efficiently match new messages against known templates in O(1)
average time.

Configuration:
- `sim_th = 0.4` - similarity threshold for template matching (lower = more aggressive clustering)
- `depth = 4` - parse tree depth
- `max_clusters = 1024` - max number of distinct templates to track

#### Step 4: Anomaly Detection - Isolation Forest (`main.py:288-349`)

**What is Isolation Forest?**

An unsupervised anomaly detection algorithm. "Unsupervised" means it learns
what "normal" looks like without labeled examples - you don't tell it "this
is an attack" or "this is normal". It figures it out from the data
distribution.

**How it works (conceptually):**

Imagine your 8-dimensional feature vectors as points in space. Normal events
cluster together in dense regions. Anomalies sit in sparse regions, far from
the clusters.

Isolation Forest builds 200 random binary trees. Each tree randomly selects
a feature and a split value, recursively partitioning the space. An anomalous
point is "easy to isolate" - it takes few splits to separate it from
everything else (short path length). Normal points are "hard to isolate" -
they're surrounded by similar points and require many splits (long path
length).

The **anomaly score** is derived from the average path length across all
200 trees:
- Negative scores (e.g., -0.4) = more anomalous (short path = easy to isolate)
- Positive scores (e.g., +0.2) = more normal (long path = hard to isolate)
- Score of 0 = borderline

**Training cycle (`main.py:331-349`):**

1. The model collects the first `TRAINING_WINDOW` events (default: 5000)
   into a buffer. During this warmup, a simple heuristic is used instead:
   if `suspicious_score > 0.3`, flag it.
2. After 5000 events, `StandardScaler` normalizes the features (zero mean,
   unit variance) and the Isolation Forest fits on the data. A larger
   training window captures more diversity in "normal" log traffic, which
   is critical for environments with many different log sources.
3. The model retrains every `TRAINING_WINDOW` events (rolling window of
   2x the training window size) to adapt to changing log patterns.
4. The `contamination` parameter (default: 0.01) tells the model to expect
   ~1% of events to be anomalous. This affects the internal decision boundary.
   Setting this too high (e.g., 0.05) forces the model to flag normal-but-diverse
   events to fill the anomaly quota.

**Decision threshold (`main.py:328`):**

After scoring, an event is flagged as anomalous if:
```
score < ANOMALY_THRESHOLD  (default: -0.4)
```

**Tuning parameters:**

| Parameter | Default | Effect of increasing | Effect of decreasing |
|-----------|---------|---------------------|---------------------|
| `ANOMALY_THRESHOLD` | `-0.4` | More events flagged (more sensitive) | Fewer events flagged (stricter) |
| `TRAINING_WINDOW` | `5000` | Better baseline but slower to start | Faster start but narrower baseline |
| `CONTAMINATION` | `0.01` | Model expects more anomalies, flags more | Model expects fewer anomalies, flags less |

**Why these particular features and this model?**

Isolation Forest was chosen because:
- Works well with mixed feature types (continuous + categorical)
- Handles high-dimensional data efficiently
- Doesn't require labeled training data
- Very fast inference on CPU (~microseconds per event)
- Naturally adapts to whatever "normal" looks like in your environment

The 8 features were chosen to capture different dimensions of "unusual":
temporal (hour_of_day), structural (template_id_hash, msg_word_count), rarity
(template_rarity, process_ratio), semantic (severity, suspicious_score),
and physical (message_length).

#### Step 5: Indexing (`main.py:970-989`)

Every event gets indexed to `logs-processed` with its anomaly score.

Anomalous events additionally get:
- A UUID document ID
- Indexed to `logs-anomalies` with `llm_analyzed=false`
- Submitted to the LLM worker queue (non-blocking)

Bulk indexing batches up to `BATCH_SIZE` (default: 50) documents before
flushing to OpenSearch, reducing network overhead.

### 4. AI Service - LLM Worker (`main.py:447-585`)

A separate background thread that processes anomalous events through the
local LLM. **The main thread never blocks on LLM calls.**

**Architecture:**

```
Main Thread                    LLM Worker Thread
───────────                    ─────────────────
                               
anomaly detected ──> Queue ──> BLPOP from queue
                    (bounded   │
                     10000     ▼
                     items)    Build prompt with:
                                - raw log line
                                - hostname, process
                                - anomaly score
                                - pattern matches
                                - log template
                               │
                               ▼
                               POST to Ollama /api/generate
                               (5-30 seconds on CPU)
                               │
                               ▼
                               Parse JSON response
                               │
                               ▼
                               UPDATE doc in OpenSearch
                               (logs-anomalies/{doc_id})
                               sets llm_analyzed=true
```

**LLM prompt (`main.py:355-369`):**

The prompt provides the LLM with:
- The raw syslog line
- Contextual metadata (hostname, process, anomaly score, pattern matches, template)
- Instruction to respond in a specific JSON format

**LLM response format:**
```json
{
  "threat_category": "brute_force",
  "severity": "high",
  "explanation": "Multiple failed SSH login attempts from known Tor exit node IP.",
  "recommended_action": "Block source IP and review auth logs for successful logins."
}
```

**Threat categories:** `brute_force`, `privilege_escalation`, `service_failure`,
`resource_exhaustion`, `network_anomaly`, `configuration_error`,
`data_exfiltration`, `benign_anomaly`, `unknown`

**Severity levels:** `critical`, `high`, `medium`, `low`, `info`

**Queue overflow handling:**

If the LLM can't keep up and the queue reaches `LLM_QUEUE_SIZE` (default:
10000), new anomalies are dropped from the queue. When dropped, the
OpenSearch document is updated with `llm_skipped=true` so the dashboard
can distinguish "genuinely pending" from "permanently skipped" events.

**Why async?** On CPU, even small LLMs take seconds per event. If 1% of
incoming events are anomalous and you receive 10 events/sec, that's ~6
anomalies/minute. Without async, every LLM call would stall the main
loop, causing the Redis input queue to grow and Layer 1 to fall behind.

### 5. Ollama (LLM Runtime)

Ollama manages the local LLM model. It handles model loading, memory
management, and inference.

**Default model:** Qwen3.5-0.8B (quantized)
- 0.8 billion parameters
- ~1GB disk / ~1.5GB RAM
- ~60-120 tokens/sec on modern CPUs
- Native structured output (JSON) and tool calling support
- Thinking mode disabled via `/no_think` prompt suffix for speed

**Why this model?**
- Small enough to run fast on CPU (~2-10 seconds per event)
- Qwen3.5 family has strong structured output capabilities at every size
- Much faster than 3B+ models while still providing useful classification
- Thinking mode can be disabled to avoid wasting tokens on internal reasoning

**Thinking mode:** Qwen3/3.5 models support a "thinking" mode that wraps
internal reasoning in `<think>...</think>` blocks. For our use case, thinking
wastes CPU cycles generating tokens we don't need. The prompt includes
`/no_think` to disable this, and the response parser strips any `<think>`
blocks as a fallback.

**Alternatives:**
- `qwen3.5:2b` - better accuracy, ~2-3x slower
- `qwen3.5:9b` - significantly more accurate, needs ~8GB RAM
- `ministral-3:3b` - strong structured output, newer Mistral architecture
- `qwen2.5:3b` - previous default, good quality but slower on CPU

### 6. OpenSearch + Dashboards

**Three indices:**

| Index | Content | Retention |
|-------|---------|-----------|
| `logs-processed` | Every event with anomaly score, features, metadata | All events |
| `logs-anomalies` | Only flagged events. Initially `llm_analyzed=false`, updated to `true` with LLM results via async worker | Anomalies only |
| `logs-stats` | Processing statistics every 30 seconds: events/sec, anomaly rate, LLM queue depth, latency | Time series |

**Field mappings (key fields):**

```
hostname            keyword    (aggregatable)
process             keyword    (aggregatable)
severity            keyword    (aggregatable)
anomaly_score       float      (range queries, histograms)
is_anomaly          boolean    (filter)
suspicious_categories keyword  (terms aggregation)
template_str        keyword    (terms aggregation)
llm_analyzed        boolean    (filter: true/false)
llm_threat_category keyword    (terms aggregation)
llm_severity        keyword    (terms aggregation)
llm_explanation     text       (full-text search)
```

**Dashboard layout:**

```
┌──────────────────────────────────────────────────────────────┐
│ ROW 1: LLM-ANALYZED RESULTS (high-value, filtered)           │
│ ┌──────────────┬──────────────┬──────────┬──────────┐        │
│ │ Threat       │ LLM Severity │ Pending  │ LLM Queue│        │
│ │ Categories   │ Breakdown    │ LLM Count│ Depth    │        │
│ │ (donut)      │ (bar)        │ (metric) │ (line)   │        │
│ └──────────────┴──────────────┴──────────┴──────────┘        │
│                                                               │
│ ROW 2: LLM DETAIL TABLE                                      │
│ ┌────────────────────────────────────────────────────────┐    │
│ │ timestamp | host | process | threat | severity |       │    │
│ │           |      |         | category|         |       │    │
│ │           |      |         |        | explanation | ... │    │
│ │ (filtered: llm_analyzed=true AND NOT benign_anomaly)   │    │
│ └────────────────────────────────────────────────────────┘    │
│                                                               │
│ ROW 3: LAYER 1 ML OVERVIEW (all events)                      │
│ ┌──────────────┬──────────────┬──────────────┐               │
│ │ Events Over  │ Anomaly Score│ Top Anomalous│               │
│ │ Time (area)  │ Distribution │ Hosts (table)│               │
│ │ normal/anom  │ (histogram)  │              │               │
│ └──────────────┴──────────────┴──────────────┘               │
│                                                               │
│ ROW 4: SYSTEM STATS                                          │
│ ┌──────────────┬──────────────┬──────────────┐               │
│ │ Suspicious   │ Processing   │ Anomaly Rate │               │
│ │ Patterns     │ Throughput   │ (%)          │               │
│ │ (tag cloud)  │ (events/sec) │ (line chart) │               │
│ └──────────────┴──────────────┴──────────────┘               │
└──────────────────────────────────────────────────────────────┘
```

### 7. Anomaly Injection Script (`scripts/inject-anomalies.sh`)

Uses the `logger` command to inject realistic anomalous events into
`/var/log/messages`. Events flow through syslog-ng -> syslog-receiver ->
Redis -> AI service, testing the full pipeline end-to-end.

**8 scenarios:**

| Scenario | What it generates |
|----------|-------------------|
| `brute_force` | SSH failed password attempts from attack IPs, burst patterns |
| `oom` | Kernel OOM kills with realistic memory stats |
| `segfault` | Process segfaults, SEGV signals, service crashes |
| `privesc` | Failed sudo/su attempts, auth failures for root |
| `disk_full` | EXT4 errors, "No space left on device" |
| `network` | SYN flooding, conntrack table full |
| `service_failure` | systemd restart loops, exit-code failures |
| `access_denied` | AppArmor denials, auth disconnect |

---

## Data Flow Summary

```
1. Log event enters the system
   ├── via syslog-ng TCP/UDP -> syslog-receiver -> Redis
   ├── via Filebeat -> Redis
   └── via synthetic generator -> file (demo mode)

2. AI Service main thread consumes from Redis (BLPOP)
   └── ~microseconds latency

3. Syslog parsing extracts hostname, process, pid, message
   └── Handles RFC 3164 priority prefix (<13>, <191>, etc.)

4. Drain3 extracts log template
   └── "Failed password for <*> from <*> port <*> ssh2"

5. Feature extraction produces 8-dimensional vector
   └── [msg_len, severity, suspicious_score, template_hash,
        template_rarity, hour, process_ratio, msg_word_count]

6. Isolation Forest scores the vector
   ├── score > ANOMALY_THRESHOLD (-0.4) -> normal (95-99% of events)
   │   └── Index to logs-processed only
   └── score < ANOMALY_THRESHOLD -> ANOMALY (1-5% of events)
       ├── Index to logs-processed
       ├── Index to logs-anomalies (llm_analyzed=false)
       └── Submit to LLM queue (non-blocking)

7. LLM worker (background thread) picks up anomalies
   ├── Builds prompt with log line + context
   ├── Sends to Ollama (5-30 sec on CPU)
   ├── Parses JSON response (threat_category, severity, explanation)
   └── Updates the document in OpenSearch (llm_analyzed=true)

8. OpenSearch Dashboards displays results
   ├── Top rows: LLM-analyzed threats only (filtered)
   └── Bottom rows: All events, ML stats
```

---

## Performance Characteristics

| Component | Throughput | Latency | Bottleneck? |
|-----------|-----------|---------|-------------|
| Syslog receiver | Thousands/sec | <1ms | No |
| Redis | 100K+ ops/sec | <1ms | No |
| Syslog parsing | Thousands/sec | ~microseconds | No |
| Drain3 template mining | Thousands/sec | ~microseconds | No |
| Feature extraction | Thousands/sec | ~microseconds | No |
| Isolation Forest scoring | Thousands/sec | ~microseconds | No |
| OpenSearch bulk indexing | Hundreds/sec | ~10ms per batch | No |
| **LLM inference (CPU)** | **6-30/min** | **2-10 sec** | **YES** |

The LLM is the only bottleneck, which is why:
1. It runs asynchronously in a background thread
2. Only ~1% of events reach it (after Isolation Forest filtering)
3. A bounded queue (10000) with `llm_skipped` tracking prevents memory exhaustion
4. The dashboard shows events immediately from Layer 1, LLM results appear later

**PoC metric to extract:** "With GPU, LLM throughput would increase
dramatically, handling a much higher anomaly rate and enabling larger models."

---

## Configuration Reference

All settings via environment variables in `docker-compose.yml`:

| Variable | Default | Description |
|----------|---------|-------------|
| `INPUT_MODE` | `redis` | `redis` or `file` |
| `ANOMALY_THRESHOLD` | `-0.4` | Score cutoff (more negative = stricter) |
| `TRAINING_WINDOW` | `5000` | Events before first model training |
| `CONTAMINATION` | `0.01` | Expected anomaly fraction (0.01 = 1%) |
| `LLM_MODEL` | `qwen3.5:0.8b` | Ollama model name |
| `LLM_ENABLED` | `true` | Enable/disable LLM layer |
| `LLM_WORKERS` | `1` | Number of LLM worker threads |
| `LLM_QUEUE_SIZE` | `10000` | Max queued anomalies for LLM |
| `BATCH_SIZE` | `50` | OpenSearch bulk batch size |

---

## File Structure

```
ai_log_filter/
├── docker-compose.yml              # All services: OpenSearch, Dashboards, Redis,
│                                   #   Ollama, syslog-receiver, ai-service
├── ai-service/
│   ├── Dockerfile
│   ├── requirements.txt            # numpy, scikit-learn, opensearch-py, drain3,
│   │                               #   requests, redis
│   └── main.py                     # ~1030 lines: the entire AI pipeline
│       ├── Syslog parser           #   lines 93-156
│       ├── Feature extraction      #   lines 190-273
│       ├── Isolation Forest        #   lines 288-349
│       ├── Ollama integration      #   lines 352-444
│       ├── Async LLM worker        #   lines 447-585
│       ├── OpenSearch client       #   lines 588-704
│       ├── Stats tracker           #   lines 707-772
│       ├── Input sources           #   lines 775-868
│       └── Main loop               #   lines 872-1034
│
├── syslog-receiver/
│   ├── Dockerfile
│   ├── requirements.txt            # redis only
│   └── receiver.py                 # TCP+UDP syslog -> Redis
│
├── sample-logs/
│   ├── Dockerfile
│   └── generate_syslog.py          # Synthetic log generator with anomalies
│
├── dashboards/
│   └── setup-dashboards.sh         # Creates index patterns, visualizations,
│                                   #   and dashboard via REST API
├── filebeat/
│   └── filebeat.yml                # Reference config for Filebeat (alternative
│                                   #   to syslog-ng, outputs to Redis)
├── scripts/
│   └── inject-anomalies.sh         # 8 anomaly scenarios via logger command
│
├── .env.example                    # Proxy config template
├── pip.conf.example                # Corporate PyPI mirror template
└── README.md                       # Setup and usage guide
```
