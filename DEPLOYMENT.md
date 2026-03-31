# Deployment Guide

Step-by-step guide to deploy the AI Log Filter from scratch on a server.

## Prerequisites

- Docker and Docker Compose (v2+)
- Network access to Kafka brokers (port 9093 + broker ports 9093-9993)
- Network access to Ollama servers (port 11434)
- Kafka mTLS certificates (client cert + key + CA cert)
- At least one Ollama server running with a model pulled

## Server Layout

### Current production setup

```
MAIN SERVER (Docker stack):
  - OpenSearch + Dashboards (visualization)
  - Redis (L2->L3 queue only)
  - HAProxy (load balancer for Ollama pools)
  - ai-service (Layer 1 ML + Layer 2 LLM consumer)
  - layer3-engine (Layer 3 correlation)

OLLAMA SERVERS (bare metal, not in Docker):
  Layer 2 pool (fast, small model - qwen2.5:0.5b):
    - Server A: 64 threads, OLLAMA_NUM_PARALLEL=4
    - Server B: 64 threads, OLLAMA_NUM_PARALLEL=4
    - Server C: 32 threads, OLLAMA_NUM_PARALLEL=2

  Layer 3 pool (slower, larger model - qwen2.5:3b):
    - Server D: 48 threads, OLLAMA_NUM_PARALLEL=3
    - Server E: 48 threads, OLLAMA_NUM_PARALLEL=3
```

## Step 1: Clone the Repository

```bash
git clone <repo-url> ai_log_filter
cd ai_log_filter
```

## Step 2: Configure Ollama Servers

On EACH bare metal Ollama server:

### 2a. Install Ollama

```bash
curl -fsSL https://ollama.com/install.sh | sh
```

### 2b. Configure Ollama systemd override

```bash
sudo mkdir -p /etc/systemd/system/ollama.service.d

sudo tee /etc/systemd/system/ollama.service.d/override.conf <<'EOF'
[Service]
Environment="OLLAMA_HOST=0.0.0.0:11434"
Environment="OLLAMA_NUM_PARALLEL=4"
Environment="OLLAMA_KEEP_ALIVE=-1"
EOF

sudo systemctl daemon-reload
sudo systemctl enable ollama
sudo systemctl restart ollama
```

**Adjust `OLLAMA_NUM_PARALLEL` per server:**

| Server threads | Recommended NUM_PARALLEL |
|---|---|
| 32 threads (16 physical) | 2 |
| 48 threads (24 physical) | 3 |
| 64 threads (32 physical) | 4 |
| 96 threads (48 physical) | 6 |

### 2c. Pull the model

**Layer 2 servers (fast/small model):**
```bash
ollama pull qwen2.5:0.5b
```

**Layer 3 servers (larger/smarter model):**
```bash
ollama pull qwen2.5:3b
```

### 2d. Verify

```bash
curl http://localhost:11434/api/tags
# Should list the pulled model
```

### 2e. If using a corporate proxy for model downloads

Add to the override before `daemon-reload`:
```bash
sudo tee -a /etc/systemd/system/ollama.service.d/override.conf <<'EOF'
Environment="HTTP_PROXY=http://proxy.corp.example.com:8080"
Environment="HTTPS_PROXY=http://proxy.corp.example.com:8080"
Environment="NO_PROXY=localhost,127.0.0.1"
EOF
sudo systemctl daemon-reload
sudo systemctl restart ollama
```

## Step 3: Configure HAProxy

### 3a. Create HAProxy config from template

```bash
cp haproxy/haproxy.cfg.example haproxy/haproxy.cfg
```

### 3b. Edit haproxy/haproxy.cfg

Replace the placeholder server addresses with your actual Ollama server
hostnames/IPs:

```
# Layer 2 backend (port 11434):
backend ollama_l2_servers
    balance leastconn
    option httpchk GET /api/tags
    http-check expect status 200
    server l2-srv1 <L2_SERVER_1_HOSTNAME>:11434 check inter 10s fall 3 rise 2
    server l2-srv2 <L2_SERVER_2_HOSTNAME>:11434 check inter 10s fall 3 rise 2
    server l2-srv3 <L2_SERVER_3_HOSTNAME>:11434 check inter 10s fall 3 rise 2

# Layer 3 backend (port 11435):
backend ollama_l3_servers
    balance leastconn
    option httpchk GET /api/tags
    http-check expect status 200
    server l3-srv1 <L3_SERVER_1_HOSTNAME>:11434 check inter 10s fall 3 rise 2
    server l3-srv2 <L3_SERVER_2_HOSTNAME>:11434 check inter 10s fall 3 rise 2
```

**Important:** `haproxy/haproxy.cfg` is gitignored (contains real hostnames).
Only `haproxy/haproxy.cfg.example` is tracked in git.

## Step 4: Configure Kafka mTLS Certificates

### 4a. Obtain certificates

You need three files:
- `ca.crt` - CA certificate that signed the Kafka broker certificates
- `client.crt` - Client certificate (must have "TLS Web Client Authentication" extension)
- `client.key` - Client private key

**If you have JKS keystores, convert to PEM:**

```bash
# Extract CA from truststore
keytool -exportcert -alias <alias> -keystore consumer.truststore.jks -rfc -file ca.crt
# Tip: use 'keytool -list -keystore consumer.truststore.jks' to find the alias

# Convert client keystore to PEM
keytool -importkeystore \
  -srckeystore consumer.keystore.jks \
  -destkeystore temp.p12 \
  -deststoretype PKCS12
openssl pkcs12 -in temp.p12 -clcerts -nokeys -out client.crt
openssl pkcs12 -in temp.p12 -nocerts -nodes -out client.key
rm temp.p12
```

**If you have raw .crt and .key files from OpenSSL/ServiceDesk:**
```bash
# Just copy them directly
cp project.crt client.crt
cp project.key client.key
```

### 4b. Place certificates

```bash
mkdir -p certs
cp ca.crt certs/ca.crt
cp client.crt certs/client.crt
cp client.key certs/client.key
chmod 644 certs/ca.crt certs/client.crt
chmod 600 certs/client.key
```

**Important:** `certs/` contents are gitignored (except README.md).

### 4c. Verify certificates

```bash
# Check cert details
openssl x509 -in certs/client.crt -text -noout | grep -A1 "Extended Key Usage"
# Should show: TLS Web Client Authentication

# Test TLS connection to Kafka broker
openssl s_client -connect <kafka-broker>:9093 \
  -cert certs/client.crt \
  -key certs/client.key \
  -CAfile certs/ca.crt
```

## Step 5: Create .env Configuration

```bash
cp .env.example .env
```

Edit `.env` with your actual values. Key settings:

```bash
# --- Kafka ---
INPUT_MODE=kafka
KAFKA_BROKERS=<kafka-broker-hostname>:9093
KAFKA_TOPIC=<your-log-topic>
KAFKA_GROUP_ID=ai-log-filter
KAFKA_SSL_ENDPOINT_ALGO=none          # required if Kafka is behind HA proxy
# KAFKA_SSL_KEY_PASSWORD=<password>   # only if key is password-protected

# --- Rate limiter ---
RATE_LIMIT_PER_SEC=0                  # 0=unlimited, or set to e.g. 5000

# --- Ollama (via HAProxy) ---
OLLAMA_HOST=http://haproxy:11434      # L2 pool
L3_OLLAMA_HOST=http://haproxy:11435   # L3 pool (separate servers)

# --- LLM models ---
LLM_MODEL=qwen2.5:0.5b               # Layer 2 (fast, on L2 servers)
L3_LLM_MODEL=qwen2.5:3b              # Layer 3 (smarter, on L3 servers)
LLM_WORKERS=12                        # L2 pool capacity + 2 headroom

# --- Layer 3: Production ES (optional but recommended) ---
PROD_ES_HOST=https://elasticsearch.example.com:9200
PROD_ES_USER=readonly_user
PROD_ES_PASS=<password>
PROD_ES_INDEX=logs-*
PROD_ES_VERIFY_CERTS=false

# --- Layer 3 toggle ---
L3_ENABLED=true
```

## Step 6: Build and Start

```bash
# Build all containers (first time takes a few minutes)
docker compose up -d --build

# Verify all containers are running
docker compose ps

# Expected containers:
#   opensearch            - running (healthy)
#   opensearch-dashboards - running
#   redis                 - running (healthy)
#   haproxy               - running
#   ai-log-service        - running
#   layer3-engine         - running
```

## Step 7: Setup Dashboards

```bash
# Wait ~2 minutes for OpenSearch to be fully ready, then:
./dashboards/setup-dashboards.sh

# Open dashboard:
# http://<server>:5601/app/dashboards#/view/dashboard-ai-log-filter
```

## Step 8: Verify Data Flow

```bash
# 1. Check ai-service is consuming from Kafka
docker logs ai-log-service -f
# Should show: [kafka] Subscribed to topic 'xxx'. Consuming...
# Then: STATS | total=N anomalies=M rate=X% eps=Y ...

# 2. Check HAProxy sees Ollama servers
# Open http://<server>:8405/stats
# All L2 and L3 servers should show green (UP)

# 3. Check Layer 3 is processing
docker logs layer3-engine -f
# Should show: Processing [category/severity] from hostname ...

# 4. Check Redis L3 queue depth
docker exec redis redis-cli LLEN layer3:queue

# 5. Check OpenSearch has data
curl -s http://localhost:9200/logs-processed/_count
curl -s http://localhost:9200/logs-anomalies/_count
curl -s http://localhost:9200/logs-threats/_count
```

## Troubleshooting

### Kafka connection issues

```bash
# Check if ai-service can reach Kafka
docker logs ai-log-service 2>&1 | grep -i "kafka\|ssl\|error" | tail -20

# Common issues:
# - "SSL handshake failed" -> CA cert doesn't match broker's CA
# - "No such file" -> certs not mounted, check certs/ directory
# - "Connection refused" -> network access blocked, check firewall rules
# - "Unknown topic" -> topic doesn't exist or no permissions
```

### HAProxy not routing to Ollama servers

```bash
# Check HAProxy logs
docker logs haproxy 2>&1 | tail -20

# Check server health
# Open http://<server>:8405/stats
# Servers showing "DOWN" = can't reach Ollama on that host

# Test from inside HAProxy container
docker exec haproxy wget -qO- http://<ollama-hostname>:11434/api/tags
```

### Layer 2 LLM not analyzing events

```bash
# Check LLM worker logs
docker logs ai-log-service 2>&1 | grep "llm-worker\|ANALYZED\|no result" | tail -20

# If "no result" count is high: LLM responses are failing to parse
# If "ANALYZED" count is 0: LLM can't connect to Ollama via HAProxy

# Check model is available on L2 servers
curl -s http://<l2-server>:11434/api/tags
# Should list qwen2.5:0.5b
```

### Layer 3 not producing results

```bash
# Check L3 logs
docker logs layer3-engine 2>&1 | tail -30

# Check L3 queue
docker exec redis redis-cli LLEN layer3:queue

# Check logs-threats index
curl -s http://localhost:9200/logs-threats/_count

# If count is 0 but queue is being consumed:
# Check for "Failed to index" errors in L3 logs
docker logs layer3-engine 2>&1 | grep -i "failed\|error" | tail -20
```

### High anomaly rate (>10%)

This means Layer 1 is flagging too many events. Adjust:
```bash
# In docker-compose.yml or .env:
ANOMALY_THRESHOLD=-0.7     # stricter (was -0.6)
TRAINING_WINDOW=10000      # more training data (was 5000)
CONTAMINATION=auto         # let sklearn decide
ALLOWLIST_MIN_PCT=0.5      # allowlist more templates (was 1.0)
```

Then: `docker compose up -d --build` and `docker compose down -v` (wipe data,
re-train from scratch).

### Dashboard shows no data

```bash
# Re-run dashboard setup
./dashboards/setup-dashboards.sh

# Check if indices have data
curl -s http://localhost:9200/_cat/indices?v
```

## Network Requirements

| From | To | Port | Protocol | Purpose |
|---|---|---|---|---|
| Docker host | Kafka bootstrap | 9093 | TCP/SSL | Kafka consumer |
| Docker host | Kafka brokers | 9093-9993 | TCP/SSL | Kafka data |
| Docker host | Ollama L2 servers | 11434 | TCP | LLM inference |
| Docker host | Ollama L3 servers | 11434 | TCP | LLM inference |
| Docker host | Production ES | 9200 | TCP/HTTPS | L3 correlation queries |
| Browser | Docker host | 5601 | TCP | OpenSearch Dashboards |
| Browser | Docker host | 8405 | TCP | HAProxy stats |

## Updating

```bash
cd ai_log_filter
git pull

# If only dashboard/config changes:
./dashboards/setup-dashboards.sh

# If Python code changed:
docker compose up -d --build

# If feature dimensions changed (rare):
docker compose down -v    # wipes all data
docker compose up -d --build
./dashboards/setup-dashboards.sh
```

## Ports Summary

| Port | Service | Description |
|---|---|---|
| 5601 | OpenSearch Dashboards | Web UI for visualization |
| 8405 | HAProxy stats | Load balancer monitoring |
| 9200 | OpenSearch API | Direct API access |
| 6379 | Redis | Internal L3 queue (not needed externally) |

## Docker Compose Profiles

| Command | What starts |
|---|---|
| `docker compose up -d` | Core stack (OpenSearch, Redis, HAProxy, ai-service, layer3-engine) |
| `docker compose --profile syslog up -d` | + syslog-receiver (for non-Kafka input) |
| `docker compose --profile demo up -d` | + synthetic log generator (testing only) |

## Files That Need Manual Configuration (Not in Git)

| File | Template | Purpose |
|---|---|---|
| `.env` | `.env.example` | All environment configuration |
| `haproxy/haproxy.cfg` | `haproxy/haproxy.cfg.example` | Ollama server addresses |
| `certs/ca.crt` | - | Kafka CA certificate |
| `certs/client.crt` | - | Kafka client certificate |
| `certs/client.key` | - | Kafka client private key |
