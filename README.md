# AI Log Filter

CPU-based AI log filtering and anomaly detection for SIEM environments.
Three-layer architecture: ML scoring -> LLM classification -> threat correlation.

## Architecture

```
Kafka (mTLS) ──> AI Service (Layer 1 + Layer 2) ──> OpenSearch + Dashboards
                       │              │
                  Isolation Forest   HAProxy:11434 ──> Ollama L2 pool
                  (microseconds)     (qwen2.5:0.5b)
                       │
                  high/critical
                       │
                  Redis queue
                       │
                  Layer 3 Engine
                       │
                  HAProxy:11435 ──> Ollama L3 pool
                  (qwen2.5:3b)
                       │
                  Production ES query
                       │
                  logs-threats ──> Dashboard
```

### Three Layers

| Layer | What it does | Speed | Technology |
|---|---|---|---|
| **Layer 1** | ML anomaly scoring on every event | ~thousands/sec | Drain3 + Isolation Forest |
| **Layer 2** | LLM threat classification on anomalies only | ~10-40/min per server | Ollama (small model) |
| **Layer 3** | Correlation with historical data, breach detection | ~5-15/min per server | Ollama (larger model) + ES queries |

### Key Features

- **Kafka mTLS consumer** with configurable rate limiting
- **Template allowlisting** - high-frequency log templates automatically bypass scoring
- **Async LLM workers** - Layer 1 never blocks on LLM inference
- **Multi-server Ollama** via HAProxy load balancer with separate L2/L3 pools
- **Breach detection** - bidirectional correlation scoped to same source IP + username
- **Thinking mode disabled** for Ollama models (`think: false` API parameter)

## Quick Start

See **[DEPLOYMENT.md](DEPLOYMENT.md)** for the complete step-by-step guide.

```bash
# 1. Clone and configure
git clone <repo-url> ai_log_filter && cd ai_log_filter
cp .env.example .env                          # edit with your values
cp haproxy/haproxy.cfg.example haproxy/haproxy.cfg  # edit with Ollama server IPs
mkdir -p certs && cp /path/to/*.crt /path/to/*.key certs/  # Kafka mTLS certs

# 2. Build and start
docker compose up -d --build

# 3. Setup dashboards
./dashboards/setup-dashboards.sh

# 4. Open dashboard
# http://<server>:5601/app/dashboards#/view/dashboard-ai-log-filter
```

## Dashboard

7-row dashboard with clear Layer 1/2/3 labeling:

| Row | Content |
|---|---|
| 1 | Layer 3: Total Analyzed, Confirmed Threats, Confirmed vs FP, Attack Types |
| 2 | Layer 3: Confirmed Threats Detail (with correlated events) |
| 3 | Layer 3: All Results (confirmed + false positive + failed) |
| 4 | Layer 2: Threat Categories, Severity, L2 Pending, L3 Pending, Queue Depth |
| 5 | Layer 2: LLM Analysis Results |
| 6 | Layer 1: Events Over Time, Anomaly Score Distribution, Top Hosts |
| 7 | Layer 1: Suspicious Patterns, Throughput, Anomaly Rate |

## Input Modes

| Mode | Command | Source |
|---|---|---|
| **kafka** (default) | `docker compose up -d` | Kafka topic with mTLS |
| **redis** | `INPUT_MODE=redis` + `--profile syslog` | syslog-ng -> syslog-receiver -> Redis |
| **file** | `INPUT_MODE=file` + `--profile demo` | Synthetic log generator |

## Configuration

All via `.env` file (see `.env.example` for complete reference).

### Key settings

| Variable | Default | Description |
|---|---|---|
| `INPUT_MODE` | `kafka` | Input source |
| `KAFKA_BROKERS` | `kafka:9093` | Kafka bootstrap servers |
| `KAFKA_TOPIC` | `logs` | Topic to consume |
| `KAFKA_SSL_ENDPOINT_ALGO` | `none` | Set to `none` for HA proxy |
| `KAFKA_SSL_KEY_PASSWORD` | (empty) | Only if private key is password-protected |
| `RATE_LIMIT_PER_SEC` | `0` | Max events/sec (0=unlimited) |
| `LLM_MODEL` | `qwen2.5:0.5b` | Layer 2 model |
| `L3_LLM_MODEL` | `qwen2.5:3b` | Layer 3 model |
| `LLM_WORKERS` | `12` | Concurrent LLM requests |
| `ANOMALY_THRESHOLD` | `-0.6` | Score cutoff (more negative = stricter) |
| `TRAINING_WINDOW` | `5000` | Events before first ML training |
| `CONTAMINATION` | `auto` | Anomaly fraction (`auto` or float) |
| `ALLOWLIST_MIN_PCT` | `1.0` | Templates >N% of events are skipped |

### Tuning

- **Too many false positives?** Lower threshold (`-0.7`), increase training window (`10000`), lower allowlist (`0.5`)
- **Missing real anomalies?** Raise threshold (`-0.4`), raise allowlist (`3.0`)
- **LLM too slow?** Use smaller model (`qwen2.5:0.5b`), add more Ollama servers
- **LLM quality too low?** Use larger model (`qwen2.5:3b` or `qwen2.5:7b`)

## Documentation

- **[DEPLOYMENT.md](DEPLOYMENT.md)** - Complete server setup and deployment guide
- **[ARCHITECTURE.md](ARCHITECTURE.md)** - Technical deep dive into how each component works
- **[FUTURE.md](FUTURE.md)** - Planned features (watchlist, source-type pipelines, MCP)
- **[certs/README.md](certs/README.md)** - Kafka certificate setup and JKS conversion

## File Structure

```
ai_log_filter/
├── docker-compose.yml              # All services
├── .env.example                    # Configuration template
├── .gitignore
├── ai-service/
│   ├── Dockerfile                  # Python 3.12 + librdkafka
│   ├── requirements.txt            # numpy, sklearn, opensearch-py, drain3, confluent-kafka, redis
│   └── main.py                     # Layer 1 (Isolation Forest) + Layer 2 (LLM) + Kafka consumer
├── layer3-engine/
│   ├── Dockerfile
│   ├── requirements.txt            # redis, requests, opensearch-py, elasticsearch
│   └── engine.py                   # Layer 3 correlation + breach detection
├── haproxy/
│   ├── Dockerfile
│   └── haproxy.cfg.example         # Template (copy to haproxy.cfg, fill in servers)
├── certs/
│   └── README.md                   # Certificate setup instructions
├── syslog-receiver/                # Alternative input (syslog profile)
├── sample-logs/                    # Synthetic generator (demo profile)
├── dashboards/
│   └── setup-dashboards.sh         # Auto-provision 18 visualizations + dashboard
├── scripts/
│   ├── setup-ollama-node.sh        # Bare metal Ollama server setup
│   └── inject-anomalies.sh         # 8 anomaly injection scenarios
├── filebeat/
│   └── filebeat.yml                # Reference config for Filebeat input
├── README.md
├── DEPLOYMENT.md                   # Step-by-step deployment guide
├── ARCHITECTURE.md                 # Technical architecture documentation
└── FUTURE.md                       # Planned features
```

## OpenSearch Indices

| Index | Content |
|---|---|
| `logs-processed` | All events with anomaly scores (Layer 1 output) |
| `logs-anomalies` | Flagged events with LLM analysis (Layer 2 output) |
| `logs-threats` | Confirmed/investigated threats with correlation (Layer 3 output) |
| `logs-stats` | Processing statistics (throughput, anomaly rate, queue depth) |
