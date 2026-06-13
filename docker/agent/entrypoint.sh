#!/usr/bin/env bash
set -euo pipefail

WORKSPACE="${WORKSPACE:-/opt/proxy_lite}"
LOG_FILE="${LOG_FILE:-$WORKSPACE/agent.log}"

require_env() {
  local name="$1"
  if [ -z "${!name:-}" ]; then
    echo "[!] Missing required environment variable: $name" >&2
    exit 1
  fi
}

require_env CONTROLLER_URL
require_env AGENT_TOKEN
require_env PROXY_USER
require_env PROXY_PASS

CONTROLLER_URL="${CONTROLLER_URL%/}"

install -d -m 700 "$WORKSPACE/configs"
cd "$WORKSPACE"

cat > "$WORKSPACE/proxy-lite.env" << EOF
C2_TOKEN=$AGENT_TOKEN
PROXY_USER=$PROXY_USER
PROXY_PASS=$PROXY_PASS
EOF
chmod 600 "$WORKSPACE/proxy-lite.env"
printf "%s" "$AGENT_TOKEN" > "$WORKSPACE/agent_token"
chmod 600 "$WORKSPACE/agent_token"

echo "[1/3] Downloading agent scripts from $CONTROLLER_URL"
curl -fsSL -H "Authorization: Bearer $AGENT_TOKEN" -o lite_manager.py "$CONTROLLER_URL/scripts/lite_manager.py"
curl -fsSL -H "Authorization: Bearer $AGENT_TOKEN" -o proxy_server.py "$CONTROLLER_URL/scripts/proxy_server.py"

echo "[2/3] Validating Python scripts"
python3 -m py_compile lite_manager.py proxy_server.py

echo "[3/3] Starting proxy agent"
touch "$LOG_FILE"
python3 -u lite_manager.py 2>&1 | tee -a "$LOG_FILE"
