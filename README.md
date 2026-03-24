# AI Log Filter PoC

CPU-based AI log filtering and anomaly detection for SIEM environments.
Proof of concept to evaluate local AI capabilities before committing to dedicated AI hardware.

## What It Does

1. **Generates** synthetic syslog data with injected anomalies (brute force, OOM, segfaults, etc.)
2. **Parses** logs using Drain3 (log template extraction)
3. **Detects anomalies** using Isolation Forest (unsupervised ML, CPU-native)
4. **Classifies threats** using a small local LLM via Ollama (Qwen2.5-3B, CPU inference)
5. **Visualizes** everything in OpenSearch Dashboards

## Architecture

```
Synthetic Syslog ──> Python AI Service ──> OpenSearch + Dashboards
  (log-generator)    (main.py)              (visualization)
                         │
                     Ollama (LLM)
                     Qwen2.5-3B on CPU
```

### AI Pipeline (Two Layers)

- **Layer 1 - Classical ML (fast):** Drain3 log parsing + feature extraction + Isolation Forest.
  Handles full event volume. Runs at thousands of events/sec on CPU.
- **Layer 2 - Local LLM (slow but smart):** Only processes events flagged by Layer 1.
  Provides threat classification, severity, explanation, and recommended action.

## Prerequisites

- Docker and Docker Compose
- ~4GB RAM minimum (8GB+ recommended)
- ~3GB disk for the LLM model (downloaded on first run)

## Quick Start

```bash
# 1. Start everything
docker compose up -d

# 2. Wait ~2 minutes for OpenSearch to be ready and the AI service to initialize

# 3. Set up dashboards (run once, after OpenSearch Dashboards is ready)
./dashboards/setup-dashboards.sh

# 4. Open the dashboard
#    http://localhost:5601/app/dashboards#/view/dashboard-ai-log-filter
```

The LLM model (~2GB) will be pulled automatically on first start. This can take
several minutes depending on your connection.

## Accessing the Stack

| Service | URL |
|---------|-----|
| OpenSearch Dashboards | http://localhost:5601 |
| OpenSearch API | http://localhost:9200 |
| Ollama API | http://localhost:11434 |

## Configuration

All configuration is via environment variables in `docker-compose.yml`:

### AI Service

| Variable | Default | Description |
|----------|---------|-------------|
| `OPENSEARCH_HOST` | `http://opensearch:9200` | OpenSearch endpoint |
| `OLLAMA_HOST` | `http://ollama:11434` | Ollama endpoint |
| `LOG_FILE` | `/var/log/synthetic/syslog` | Log file to tail |
| `LLM_MODEL` | `qwen2.5:3b` | Ollama model name |
| `LLM_ENABLED` | `true` | Enable/disable LLM analysis |
| `ANOMALY_THRESHOLD` | `-0.15` | Isolation Forest anomaly threshold (more negative = stricter) |
| `TRAINING_WINDOW` | `500` | Number of events before first model training |
| `BATCH_SIZE` | `50` | OpenSearch bulk indexing batch size |

### Log Generator

| Variable | Default | Description |
|----------|---------|-------------|
| `EVENTS_PER_SEC` | `5` | Log generation rate |
| `ANOMALY_RATIO` | `0.05` | Fraction of events that are anomalous (0.05 = 5%) |

## Using with Real Syslog

To analyze real syslog instead of synthetic data:

```yaml
# In docker-compose.yml, modify ai-service volumes:
volumes:
  - /var/log:/var/log/host:ro

# And set:
environment:
  - LOG_FILE=/var/log/host/syslog
```

## Using with Kafka (Production Path)

For production, replace the file-tailing input with a Kafka consumer.
The `main.py` script is structured so the input source (`tail_file` function)
can be swapped for a Kafka consumer with minimal changes:

```python
# Replace tail_file() with:
from confluent_kafka import Consumer
consumer = Consumer({'bootstrap.servers': 'kafka:9092', 'group.id': 'ai-filter'})
consumer.subscribe(['logs-raw'])
for msg in consumer:
    yield msg.value().decode()
```

## OpenSearch Indices

| Index | Contents |
|-------|----------|
| `logs-processed` | All logs with anomaly scores |
| `logs-anomalies` | Only flagged events with LLM analysis |
| `logs-stats` | Processing statistics (throughput, anomaly rate, etc.) |

## Stopping

```bash
docker compose down

# To also remove data volumes:
docker compose down -v
```

## Tuning Tips

- **Too many false positives?** Lower `ANOMALY_THRESHOLD` (e.g., `-0.3`). Increase `TRAINING_WINDOW`.
- **Missing real anomalies?** Raise `ANOMALY_THRESHOLD` (e.g., `-0.05`).
- **LLM too slow?** Try `qwen2.5:1.5b` for faster inference, or set `LLM_ENABLED=false` to run ML-only.
- **Want a larger/smarter LLM?** Try `qwen2.5:7b` if you have enough RAM (~8GB for the model).

## What This PoC Demonstrates

- Feasibility of CPU-only AI for log analysis
- Processing throughput per CPU core
- Accuracy of anomaly detection on syslog data
- LLM inference latency on CPU
- Clear data to project "with GPU we could handle Nx more volume"
