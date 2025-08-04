#!/bin/bash
set -e

LOG_DIR="$(dirname "$0")/logs"
mkdir -p "$LOG_DIR"

# Stop previous instances to avoid port conflicts
pkill -f "uvicorn mcp_server:app" 2>/dev/null || true
pkill -f "gradio_app.py" 2>/dev/null || true
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

echo "=== Запуск MCP-сервера на порту 9000 ==="
nohup uvicorn mcp_server:app --factory --host 0.0.0.0 --port 9000 \
  > "$LOG_DIR/mcp_server.log" 2>&1 &
MCP_PID=$!

echo "=== Запуск веб-интерфейса Gradio на порту 7860 ==="
nohup python gradio_app.py > "$LOG_DIR/gradio.log" 2>&1 &
GRADIO_PID=$!

echo "Сервисы запущены: vLLM PID=$VLLM_PID, MCP PID=$MCP_PID, Gradio PID=$GRADIO_PID"
echo "Чтобы остановить: kill $VLLM_PID $MCP_PID $GRADIO_PID"
