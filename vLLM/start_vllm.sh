#!/bin/bash
set -e

MODEL="${MODEL:-Salesforce/xLAM-2-32b-fc-r}"
LOG_DIR="$(dirname "$0")/../logs"
mkdir -p "$LOG_DIR"

nohup vllm serve "$MODEL" \
  --port 8000 \
  --enable-auto-tool-choice \
  --tool-call-parser xlam \
  --tensor-parallel-size 2 \
  --api-key empty \
  > "$LOG_DIR/vllm.log" 2>&1 &
