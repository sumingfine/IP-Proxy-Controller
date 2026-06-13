#!/usr/bin/env bash
set -euo pipefail

CONTROLLER_PORT="${CONTROLLER_PORT:-${PORT:-8080}}"
export HOST="${HOST:-0.0.0.0}"
export PORT="$CONTROLLER_PORT"
export DATABASE_PATH="${DATABASE_PATH:-/data/proxy_controller.sqlite3}"
export WORKSPACE="${WORKSPACE:-/opt/proxy_lite}"
export CONTROLLER_URL="http://127.0.0.1:${CONTROLLER_PORT}"

mkdir -p "$(dirname "$DATABASE_PATH")" "$WORKSPACE/configs"

if [ ! -e /dev/net/tun ]; then
  echo "[!] /dev/net/tun is missing. Enable Koyeb privileged mode, otherwise OpenVPN cannot work." >&2
fi

cleanup() {
  local code=$?
  if [ -n "${controller_pid:-}" ]; then kill "$controller_pid" 2>/dev/null || true; fi
  if [ -n "${agent_pid:-}" ]; then kill "$agent_pid" 2>/dev/null || true; fi
  exit "$code"
}
trap cleanup EXIT INT TERM

echo "[controller] starting on port ${CONTROLLER_PORT}"
python3 -u /app/docker/controller/controller.py &
controller_pid=$!

echo "[controller] waiting for health check"
for _ in $(seq 1 60); do
  if curl -fsS "http://127.0.0.1:${CONTROLLER_PORT}/healthz" >/dev/null 2>&1; then
    break
  fi
  sleep 1
done

if ! curl -fsS "http://127.0.0.1:${CONTROLLER_PORT}/healthz" >/dev/null 2>&1; then
  echo "[!] controller did not become healthy" >&2
  exit 1
fi

echo "[agent] starting with controller ${CONTROLLER_URL}"
proxy-agent-entrypoint &
agent_pid=$!

wait -n "$controller_pid" "$agent_pid"
