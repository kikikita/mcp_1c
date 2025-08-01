echo "=== 1) Запуск MCP-сервера (mcp_server.py) на порту 9000 ==="
nohup uvicorn mcp_server:mcp --host 0.0.0.0 --port 9000 > mcp_server.log 2>&1 &
MCP_PID=$!
echo "MCP-сервер запущен, PID=$MCP_PID"

sleep 2

echo "=== 2) Запуск LLM-сервера (llm_server.py) на порту 8022 ==="
nohup uvicorn llm_server:app --host 0.0.0.0 --port 8022 > llm_server.log 2>&1 &
LLM_PID=$!
echo "LLM-сервер запущен, PID=$LLM_PID"

sleep 2

echo "=== 3) Запуск MCP-клиента (mcp_client.py) на порту 8021 ==="
nohup uvicorn mcp_client:app --host 0.0.0.0 --port 8021 > mcp_client.log 2>&1 &
CLIENT_PID=$!
echo "MCP-клиент запущен, PID=$CLIENT_PID"

echo "Чтобы остановить: kill $MCP_PID $LLM_PID $CLIENT_PID"

