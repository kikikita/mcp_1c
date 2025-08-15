# MCP Examples

This repository showcases several experiments built with the `fastmcp` framework.
Only the `MCP_1C` directory is actively maintained; the others are kept for reference.

## Repository layout

- **MCP_1C** – sample integration with 1C. Contains an MCP server with demo
  REST endpoints and a simple orchestrator. This is the recommended starting
  point for new projects.

## Directory overview

* `MCP_1C` – integration examples for 1C. Includes a `connection_test.py` script for checking the `/hs/mcp/` endpoints.

## Installation

Install the dependencies with pip:

```bash
pip install -r requirements.txt
```

## Running the MCP_1C server

1. Configure environment variables for connecting to the 1C OData service:

   - `MCP_1C_BASE` – базовый адрес OData, например `http://host/infobase/odata/standard.odata`.
   - `ONEC_USERNAME` и `ONEC_PASSWORD` – логин и пароль пользователя 1С.

   Переменные можно задать через файл `.env` или перед запуском сервиса.
2. Start the server:

```bash
python MCP_1C/mcp_server.py
```

The MCP API will be available on port 9000 by default. Clients can connect to `/hs/mcp/` on your 1C server to invoke the tools exposed by MCP.

### Example request

Once the server is running you can call the demo endpoints from another
terminal:

```bash
curl http://localhost:9000/1c/plan_accounts
```

This returns a JSON list of account objects. Similar requests can be sent to
`/1c/turnover` with query parameters `account`, `periodStart` and `periodEnd`.

## Running with Docker

The repository includes a `Dockerfile` and `docker-compose.yml` for a
containerised setup. The stack launches two services:

- **mcp-server** – FastAPI service exposing the MCP tools.
- **gradio-app** – web UI for interacting with the orchestrator.

The LLM (vLLM) server must be run separately on the host machine. Use the
provided script:

```bash
./vLLM/start_vllm.sh
```

After the model is up, start the remaining services:

```bash
docker compose up --build
```

Default ports are `9000` for the MCP server, `7860` for the Gradio UI and `8000`
for the local vLLM server. If any port is busy you can override them via
environment variables when running Compose:

```bash
MCP_PORT=9100 GRADIO_PORT=7861 docker compose up --build
```

The Gradio interface will then be available at
`http://localhost:${GRADIO_PORT}`. Set `MCP_1C_BASE`, `ONEC_USERNAME` and
`ONEC_PASSWORD` to connect to a real 1C instance.

