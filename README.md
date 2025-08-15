Вот структурированная и сжатая версия README в профессиональном стиле.

```markdown
# mcp_1c

AI финансист

---

## 1. Структура проекта

```

mcp\_1c/
├─ docker-compose.yml       # Запуск MCP-сервера и веб-UI
├─ gradio\_app.py             # Веб-интерфейс чата
├─ orchestrator.py           # Агент для LLM и MCP
├─ mcp\_server.py             # ASGI-сервер с MCP-инструментами
├─ odata\_client.py           # Клиент OData для 1С
├─ pdf\_parser.py             # Извлечение текста из PDF
├─ prompt.py                 # Системный промпт для LLM
├─ vLLM/
│  ├─ start\_vllm.sh          # Скрипт запуска LLM-сервера
│  └─ xlam\_tool\_call\_parser.py # Парсер tool-calls для vLLM
└─ logs/                     # Логи vLLM

````

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

