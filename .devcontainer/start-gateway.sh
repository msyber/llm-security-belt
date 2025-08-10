#!/usr/bin/env bash
set -euo pipefail

cd /workspaces/llm-security-belt/gateway

# ensure env exists
cp -n .env.example .env || true

# install deps if missing (resumes can lose node_modules)
[ -d node_modules ] || npm install

# avoid duplicates if resuming
pkill -f "node server.js" >/dev/null 2>&1 || true

# start in background and log
nohup node server.js > /tmp/gw.log 2>&1 &

# wait until ready (max ~30s)
for i in {1..30}; do
  if curl -sSf http://localhost:8787/metrics >/dev/null; then
    echo "✅ Gateway up on :8787"
    exit 0
  fi
  sleep 1
done

echo "⚠️ Gateway didn’t become ready; tail /tmp/gw.log"
exit 1
