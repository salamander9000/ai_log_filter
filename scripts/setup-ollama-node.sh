#!/usr/bin/env bash
# ==========================================================================
# Setup script for bare metal Ollama nodes
# ==========================================================================
#
# Run this on each bare metal server that will serve as an Ollama inference
# node in the load-balanced pool.
#
# Usage:
#   ./setup-ollama-node.sh [MODEL_NAME]
#
# Default model: qwen2.5:3b
#
# What it does:
#   1. Installs Ollama (if not already installed)
#   2. Enables and starts the Ollama systemd service
#   3. Configures Ollama to listen on all interfaces (0.0.0.0)
#   4. Pulls the specified model
#   5. Verifies the installation
#
# Prerequisites:
#   - Linux (systemd-based)
#   - Root or sudo access
#   - Network access to ollama.com (or proxy configured)
#
# ==========================================================================

set -euo pipefail

MODEL="${1:-qwen2.5:3b}"

echo "=== Ollama Node Setup ==="
echo "Model: ${MODEL}"
echo ""

# -----------------------------------------------------------------------
# 1. Install Ollama
# -----------------------------------------------------------------------
if command -v ollama &>/dev/null; then
    echo "[1/5] Ollama already installed: $(ollama --version 2>/dev/null || echo 'unknown version')"
else
    echo "[1/5] Installing Ollama..."
    curl -fsSL https://ollama.com/install.sh | sh
    echo "  -> Installed."
fi

# -----------------------------------------------------------------------
# 2. Configure Ollama to listen on all interfaces
# -----------------------------------------------------------------------
echo "[2/5] Configuring Ollama to listen on 0.0.0.0:11434..."

# Create systemd override to set OLLAMA_HOST
mkdir -p /etc/systemd/system/ollama.service.d

cat > /etc/systemd/system/ollama.service.d/override.conf <<'EOF'
[Service]
Environment="OLLAMA_HOST=0.0.0.0:11434"
# Increase number of parallel requests (default is 1)
Environment="OLLAMA_NUM_PARALLEL=4"
# Keep model loaded in memory (don't unload between requests)
Environment="OLLAMA_KEEP_ALIVE=-1"
EOF

# If proxy is needed, add it to the override
if [ -n "${HTTP_PROXY:-}" ] || [ -n "${HTTPS_PROXY:-}" ]; then
    echo "  -> Adding proxy configuration..."
    cat >> /etc/systemd/system/ollama.service.d/override.conf <<EOF
Environment="HTTP_PROXY=${HTTP_PROXY:-}"
Environment="HTTPS_PROXY=${HTTPS_PROXY:-}"
Environment="NO_PROXY=${NO_PROXY:-localhost,127.0.0.1}"
EOF
fi

systemctl daemon-reload
echo "  -> Configuration applied."

# -----------------------------------------------------------------------
# 3. Start Ollama service
# -----------------------------------------------------------------------
echo "[3/5] Starting Ollama service..."
systemctl enable ollama
systemctl restart ollama

# Wait for Ollama to be ready
for i in $(seq 1 30); do
    if curl -s http://localhost:11434/api/tags > /dev/null 2>&1; then
        echo "  -> Ollama is running."
        break
    fi
    echo "  Waiting for Ollama to start (attempt ${i}/30)..."
    sleep 2
done

# -----------------------------------------------------------------------
# 4. Pull the model
# -----------------------------------------------------------------------
echo "[4/5] Pulling model '${MODEL}'..."
ollama pull "${MODEL}"
echo "  -> Model pulled."

# -----------------------------------------------------------------------
# 5. Verify
# -----------------------------------------------------------------------
echo "[5/5] Verifying installation..."
echo ""

# Check service status
echo "Service status:"
systemctl is-active ollama && echo "  -> OK" || echo "  -> FAILED"

# Check model is available
echo ""
echo "Available models:"
ollama list

# Check API is reachable from all interfaces
echo ""
HOSTNAME_IP=$(hostname -I | awk '{print $1}')
echo "API endpoint: http://${HOSTNAME_IP}:11434"
echo "Testing API..."
if curl -s "http://localhost:11434/api/tags" | grep -q "${MODEL%%:*}"; then
    echo "  -> Model '${MODEL}' is available and ready."
else
    echo "  -> WARNING: Model may not be fully loaded yet."
fi

echo ""
echo "=== Setup complete ==="
echo ""
echo "Add this server to haproxy/haproxy.cfg:"
echo "    server ollama-$(hostname -s) ${HOSTNAME_IP}:11434 check inter 10s fall 3 rise 2"
echo ""
echo "Then reload HAProxy on the main server:"
echo "    docker compose exec haproxy kill -s HUP 1"
