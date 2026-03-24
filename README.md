# AI Log Filter PoC

CPU-based AI log filtering and anomaly detection for SIEM environments.
Proof of concept to evaluate local AI capabilities before committing to dedicated AI hardware.

## What It Does

1. **Ingests** syslog data via Filebeat -> Redis, or from a synthetic generator (demo mode)
2. **Parses** logs using Drain3 (log template extraction)
3. **Detects anomalies** using Isolation Forest (unsupervised ML, CPU-native)
4. **Classifies threats** using a small local LLM via Ollama (Qwen2.5-3B, CPU inference)
5. **Visualizes** everything in OpenSearch Dashboards

## Architecture

### Real mode - syslog-ng (recommended)

```
Remote servers                    Docker stack (AI server)
──────────────                    ────────────────────────

syslog-ng ──TCP:5514──> syslog-receiver ──> Redis ──> AI Service ──> OpenSearch
                        (container)         (buffer)                  + Dashboards
                                                          │
inject-anomalies.sh ──> /var/log/messages                Ollama (LLM)
(testing)               ──> syslog-ng (loops back)       Qwen2.5-3B on CPU
```

### Real mode - Filebeat

```
/var/log/messages ──> Filebeat ──> Redis ──> AI Service ──> OpenSearch + Dashboards
                      (host)       (buffer)
```

### Demo mode (synthetic generator)

```
log-generator ──> shared volume ──> AI Service ──> OpenSearch + Dashboards
```

Both syslog-ng and Filebeat can feed the pipeline simultaneously - they both
push to the same Redis list.

### AI Pipeline (Two Layers)

- **Layer 1 - Classical ML (fast):** Drain3 log parsing + feature extraction + Isolation Forest.
  Handles full event volume. Runs at thousands of events/sec on CPU.
- **Layer 2 - Local LLM (slow but smart):** Only processes events flagged by Layer 1.
  Provides threat classification, severity, explanation, and recommended action.

## Prerequisites

- Docker and Docker Compose
- ~4GB RAM minimum (8GB+ recommended)
- ~3GB disk for the LLM model (downloaded on first run)
- syslog-ng or Filebeat on the host/remote servers (for real mode)

## Quick Start - Real Mode (syslog-ng)

```bash
# 1. Start the stack (Redis mode is the default)
docker compose up -d

# 2. Configure syslog-ng to forward to the AI server (see below)

# 3. Wait ~2 minutes for OpenSearch + Ollama to be ready

# 4. Set up dashboards (run once)
./dashboards/setup-dashboards.sh

# 5. Open the dashboard
#    http://localhost:5601/app/dashboards#/view/dashboard-ai-log-filter

# 6. Inject some anomalies to test detection
./scripts/inject-anomalies.sh brute_force 20
./scripts/inject-anomalies.sh oom 5
./scripts/inject-anomalies.sh all 30
```

### syslog-ng configuration

Add this to your syslog-ng config (e.g., `/etc/syslog-ng/syslog-ng.conf` or a
file in `/etc/syslog-ng/conf.d/`):

```
# Forward to AI Log Filter
destination d_ai_filter {
    tcp("<AI_SERVER_IP>" port(5514));
};

log {
    source(s_sys);              # your existing source
    destination(d_ai_filter);
    # Keep existing destinations too - this is just a copy:
    # destination(d_mesg);
};
```

Replace `<AI_SERVER_IP>` with the IP of the server running the Docker stack.
Port **5514** accepts both TCP and UDP.

To forward from the **local** machine (AI server itself):

```
destination d_ai_filter {
    tcp("127.0.0.1" port(5514));
};
```

Reload syslog-ng: `sudo systemctl reload syslog-ng`

## Quick Start - Real Mode (Filebeat alternative)

```bash
# 1. Start the stack
docker compose up -d

# 2. Install Filebeat config on the host
sudo cp filebeat/filebeat.yml /etc/filebeat/filebeat.yml
sudo systemctl restart filebeat

# 3. Wait ~2 min, set up dashboards
./dashboards/setup-dashboards.sh

# 4. Inject anomalies
./scripts/inject-anomalies.sh all 30
```

## Quick Start - Demo Mode (Synthetic Logs)

```bash
# Start with demo profile (includes the synthetic log generator)
INPUT_MODE=file docker compose --profile demo up -d

# Set up dashboards
./dashboards/setup-dashboards.sh
```

## Anomaly Injection

The `scripts/inject-anomalies.sh` script injects realistic anomalous events
into `/var/log/messages` via the `logger` command (proper syslog formatting).
syslog-ng/Filebeat picks them up and pushes through the full pipeline.

```bash
./scripts/inject-anomalies.sh list              # show all scenarios
./scripts/inject-anomalies.sh brute_force 20    # 20 SSH brute force attempts
./scripts/inject-anomalies.sh oom 5             # 5 OOM kills
./scripts/inject-anomalies.sh segfault 3        # 3 segfaults/crashes
./scripts/inject-anomalies.sh privesc 10        # 10 privilege escalation attempts
./scripts/inject-anomalies.sh disk_full 3       # 3 disk full events
./scripts/inject-anomalies.sh network 5         # 5 network anomalies (SYN flood)
./scripts/inject-anomalies.sh service_failure 5 # 5 service restart failures
./scripts/inject-anomalies.sh access_denied 5   # 5 permission denied events
./scripts/inject-anomalies.sh all 30            # 30 random mixed anomalies
```

## Accessing the Stack

| Service | URL / Port |
|---------|------------|
| OpenSearch Dashboards | http://localhost:5601 |
| OpenSearch API | http://localhost:9200 |
| Ollama API | http://localhost:11434 |
| Syslog receiver | TCP+UDP port 5514 |
| Redis | localhost:6379 |

## Configuration

All configuration is via environment variables in `docker-compose.yml` or `.env`:

### AI Service

| Variable | Default | Description |
|----------|---------|-------------|
| `INPUT_MODE` | `redis` | Input source: `redis` (Filebeat) or `file` (tail log file) |
| `REDIS_HOST` | `redis://redis:6379` | Redis connection URL |
| `REDIS_KEY` | `filebeat:logs` | Redis list key to consume from |
| `LOG_FILE` | `/var/log/synthetic/syslog` | Log file to tail (when INPUT_MODE=file) |
| `OPENSEARCH_HOST` | `http://opensearch:9200` | OpenSearch endpoint |
| `OLLAMA_HOST` | `http://ollama:11434` | Ollama endpoint |
| `LLM_MODEL` | `qwen2.5:3b` | Ollama model name |
| `LLM_ENABLED` | `true` | Enable/disable LLM analysis |
| `ANOMALY_THRESHOLD` | `-0.3` | Isolation Forest anomaly threshold (more negative = stricter) |
| `TRAINING_WINDOW` | `1000` | Number of events before first model training |
| `CONTAMINATION` | `0.02` | Expected fraction of anomalies in the data (0.02 = 2%) |
| `BATCH_SIZE` | `50` | OpenSearch bulk indexing batch size |

### Log Generator (demo mode only)

| Variable | Default | Description |
|----------|---------|-------------|
| `EVENTS_PER_SEC` | `5` | Log generation rate |
| `ANOMALY_RATIO` | `0.05` | Fraction of events that are anomalous (0.05 = 5%) |

### Proxy (corporate environments)

```bash
cp .env.example .env
# Edit .env with your proxy URL
```

### Pip mirror (corporate environments)

```bash
cp pip.conf.example ai-service/pip.conf
# Edit ai-service/pip.conf with your internal PyPI mirror
```

## Redis Buffer

Redis sits between Filebeat and the AI service as a backpressure buffer.
If the AI service processes slower than the incoming rate (especially during
LLM analysis), events queue in Redis instead of being lost.

- Default max memory: 4GB (configurable in docker-compose.yml)
- Policy: `noeviction` - returns error when full rather than dropping logs
- No disk persistence - pure in-memory buffer for speed
- With 256GB RAM on the server, you can increase the limit significantly

Check Redis queue depth:
```bash
docker exec redis redis-cli LLEN filebeat:logs
```

## Using with Kafka (Production Path)

For production, the `INPUT_MODE` concept makes it easy to add a Kafka consumer
as a third input source. The architecture already separates input from processing.

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

- **Too many false positives?** Lower `ANOMALY_THRESHOLD` (e.g., `-0.4`). Increase `TRAINING_WINDOW`. Lower `CONTAMINATION` (e.g., `0.01`).
- **Missing real anomalies?** Raise `ANOMALY_THRESHOLD` (e.g., `-0.15`). Raise `CONTAMINATION` (e.g., `0.05`).
- **LLM too slow?** Try `qwen2.5:1.5b` for faster inference, or set `LLM_ENABLED=false` to run ML-only.
- **Want a larger/smarter LLM?** Try `qwen2.5:7b` if you have enough RAM (~8GB for the model).
- **Redis queue growing?** Increase `BATCH_SIZE`, or set `LLM_ENABLED=false` to speed up processing.

## What This PoC Demonstrates

- Feasibility of CPU-only AI for log analysis
- Processing throughput per CPU core
- Accuracy of anomaly detection on real syslog data
- LLM inference latency on CPU
- End-to-end pipeline: Filebeat -> Redis -> AI -> OpenSearch
- Clear data to project "with GPU we could handle Nx more volume"
