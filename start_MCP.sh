#!/bin/bash
LOG_DIR="$(dirname "$0")/logs"
mkdir -p "$LOG_DIR"

echo "=== Запуск MCP-сервера на порту 9000 ==="
nohup uvicorn mcp_server:mcp --host 0.0.0.0 --port 9000 > "$LOG_DIR/mcp_server.log" 2>&1 &
MCP_PID=$!
echo "MCP-сервер запущен, PID=$MCP_PID"

sleep 2

echo "=== Запуск веб-интерфейса Gradio ==="
nohup python gradio_app.py > "$LOG_DIR/gradio.log" 2>&1 &
GRADIO_PID=$!
echo "Gradio запущен, PID=$GRADIO_PID"

echo "Чтобы остановить: kill $MCP_PID $GRADIO_PID"
