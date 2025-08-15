# mcp\_1c

AI Финансист

---

## 1. Структура проекта

```text
mcp_1c/
├── docker-compose.yml           # запуск MCP-сервера и веб-UI
├── gradio_app.py                # веб-интерфейс чата
├── orchestrator.py              # агент LLM↔MCP
├── mcp_server.py                # ASGI-сервер с MCP-инструментами
├── odata_client.py              # клиент OData для 1С
├── pdf_parser.py                # извлечение текста из PDF
├── prompt.py                    # системный промпт для LLM
├── vLLM/
│   ├── start_vllm.sh            # запуск LLM-сервера
│   └── xlam_tool_call_parser.py # парсер tool-calls для vLLM
└── logs/                        # логи vLLM
```

---

## 2. Запуск

### 2.1 Подготовка LLM-сервера (vLLM)

```bash
cd vLLM
sh start_vllm.sh
````

* Модель: `Salesforce/xLAM-2-32b-fc-r`
* Порт: `8000`
* Лог: `../logs/vllm.log`

---

### 2.2 Конфигурация окружения

Создайте файл `.env` в корне проекта:

```env
MCP_URL=http://localhost:9003/mcp/
MCP_1C_BASE=http://192.168.18.113/TEST19/odata/standard.odata
ONEC_USERNAME=username
ONEC_PASSWORD=password
GRADIO_PORT=7860
LLM_SERVER_URL=http://host.docker.internal:8000/v1
OPENAI_API_KEY=empty
DEBUG=false
LOGO_PATH=logo.jpg
```

---

### 2.3 Запуск проекта

```bash
docker compose up --build
```

После запуска:

* **Gradio UI**: [http://localhost:7860](http://localhost:7860)
* **MCP-сервер**: [http://localhost:9003/mcp/](http://localhost:9003/mcp/)

---

## 3. Основные модули

| Модуль                               | Назначение                                                          |
| ------------------------------------ | ------------------------------------------------------------------- |
| **gradio\_app.py**                   | Веб-чат с загрузкой PDF, отправляет запросы LLM и MCP.              |
| **orchestrator.py**                  | Агент, обрабатывающий tool-calls LLM и вызывающий MCP-инструменты.  |
| **mcp\_server.py**                   | MCP-инструменты для работы с 1С: метаданные, поиск, CRUD-документы. |
| **odata\_client.py**                 | Запросы к OData API 1С (GET/POST/UPDATE/DELETE).                    |
| **pdf\_parser.py**                   | Извлечение текста из PDF (Tesseract / PaddleOCR).                   |
| **prompt.py**                        | Системный промпт с правилами и инструкциями для LLM.                |
| **vLLM/xlam\_tool\_call\_parser.py** | Приведение JSON tool-вызовов к формату OpenAI API.                  |
| **vLLM/start\_vllm.sh**              | Запуск LLM-сервера с плагином парсера.                              |

---

## 4. Логи и отладка

* **vLLM**: `logs/vllm.log`
* **MCP-сервер**: вывод в stdout, все вызовы инструментов логируются.

---

