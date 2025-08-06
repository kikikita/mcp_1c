#!/bin/bash
set -e

LOG_DIR="$(dirname "$0")/logs"
mkdir -p "$LOG_DIR"

# Stop previous instances to avoid port conflicts
pkill -f "vllm serve" 2>/dev/null || true

MODEL=${MODEL:-Salesforce/xLAM-2-32b-fc-r}

echo "=== Запуск vLLM на порту 8000 ==="
nohup vllm serve "$MODEL" \
  --port 8000 \
  --enable-auto-tool-choice \
  --tool-call-parser xlam \
  --tensor-parallel-size 2 \
  > "$LOG_DIR/vllm.log" 2>&1 &
VLLM_PID=$!

sleep 5
