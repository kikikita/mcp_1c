import os
import json, asyncio
from typing import List, Dict, Any
from openai import AsyncOpenAI
from fastmcp import Client as MCP
import logging
from log_config import setup_logging

setup_logging()
logger = logging.getLogger(__name__)


def _mcp_to_openai(tools):
    logger.debug("Available tools: %s", tools)
    return [{
        "type": "function",
        "function": {
            "name": t.name,
            "description": t.description or "",
            "parameters": t.inputSchema,
        }
    } for t in tools]

# ---------- НОВОЕ: утилиты приведения к JSON ----------


def _json_ready(x: Any) -> Any:
    """Сделать объект JSON-сериализуемым: pydantic/dataclass/obj -> dict/list/str/..."""
    # примитивы
    if x is None or isinstance(x, (str, int, float, bool)):
        return x
    # списки/кортежи
    if isinstance(x, (list, tuple)):
        return [_json_ready(i) for i in x]
    # словари
    if isinstance(x, dict):
        return {k: _json_ready(v) for k, v in x.items()}
    # pydantic v2
    if hasattr(x, "model_dump"):
        try:
            return _json_ready(x.model_dump())
        except Exception:
            pass
    # dataclass
    try:
        from dataclasses import is_dataclass, asdict
        if is_dataclass(x):
            return _json_ready(asdict(x))
    except Exception:
        pass
    # у некоторых есть .dict()
    if hasattr(x, "dict") and callable(getattr(x, "dict")):
        try:
            return _json_ready(x.dict())
        except Exception:
            pass
    # общая попытка через __dict__
    if hasattr(x, "__dict__"):
        try:
            return _json_ready(vars(x))
        except Exception:
            pass
    # падать не будем — вернём строковое представление
    return repr(x)


def _unwrap_tool_output(result: Any) -> Any:
    """
    Попробовать достать «смысловую» часть из объекта fastmcp:
    - .data если есть;
    - .content/текст если есть;
    - .result (часто обёртка);
    - иначе вернуть сам объект.
    """
    # 1) data
    data = getattr(result, "data", None)
    if data is not None:
        return data

    # 2) content
    content = getattr(result, "content", None)
    if content:
        # бывает список частей с .text
        try:
            # если это список объектов с .text
            if isinstance(content, list) and hasattr(content[0], "text"):
                return content[0].text
            return content
        except Exception:
            return content

    # 3) result (часто pydantic/dataclass-обёртка)
    inner = getattr(result, "result", None)
    if inner is not None:
        # иногда внутри опять лежит data/content
        return _unwrap_tool_output(inner)

    # 4) иначе отдаём как есть — дальше _json_ready доведёт
    return result

# ------------------------------------------------------


class SearchAgent:
    def __init__(self, mcp_cmd: str,
                 llm_url: str = "http://localhost:8000/v1",
                 model: str = "Salesforce/xLAM-2-32b-fc-r"):
        self.mcp = MCP(mcp_cmd)
        self.llm = AsyncOpenAI(base_url=llm_url, api_key=os.getenv("OPENAI_API_KEY", "empty"))
        self.model = model
        self.tools = None

    async def __aenter__(self):
        await self.mcp.__aenter__()
        await self.llm.__aenter__()
        self.tools = _mcp_to_openai(await self.mcp.list_tools())
        return self

    async def __aexit__(self, *exc):
        await self.mcp.__aexit__(*exc)
        await self.llm.__aexit__(*exc)

    async def ask(self, prompt: str,
                  system: str | None = None,
                  history: List[Dict[str, str]] | None = None) -> str:
        logger.info("User prompt: %s", prompt)
        msgs: List[Dict[str, str]] = []
        if system:
            msgs.append({"role": "system", "content": system})
        if history:
            msgs.extend(history)
        msgs.append({"role": "user", "content": prompt})

        retries = 0
        while True:
            try:
                resp = await self.llm.chat.completions.create(
                    model=self.model,
                    messages=msgs,
                    tools=self.tools,
                    tool_choice="auto",
                    extra_body={"min_tokens": 8},
                )
            except Exception as e:
                logger.exception("LLM request failed: %s", e)
                # если последний — tool, попробуем укоротить
                if msgs and msgs[-1].get("role") == "tool" and "tool_call_id" in msgs[-1] and retries < 2:
                    tool_msg = msgs.pop()
                    content = tool_msg.get("content", "")
                    truncated = content[: max(128, len(content) // 2)]
                    msgs.append({"role": "tool",
                                 "tool_call_id": tool_msg["tool_call_id"],
                                 "content": truncated})
                    retries += 1
                    continue
                return f"Ошибка при обращении к модели: {e} </Finished>"

            msg = resp.choices[0].message
            if msg.tool_calls:
                for call in msg.tool_calls:
                    args = json.loads(call.function.arguments or "{}")
                    logger.info("Calling tool %s with args %s", call.function.name, args)
                    result = await self.mcp.call_tool(call.function.name, args)

                    raw_output = _unwrap_tool_output(result)
                    jsonable_output = _json_ready(raw_output)

                    logger.info("Tool %s returned (normalized) %s", call.function.name, jsonable_output)

                    # важно: content должен быть СТРОКОЙ
                    msgs.append({
                        "role": "tool",
                        "tool_call_id": call.id,
                        "content": json.dumps(jsonable_output, ensure_ascii=False)
                    })
                continue

            if not msg.content or "</Finished>" not in msg.content:
                msgs.append({"role": "user",
                             "content": "Заверши кратким результатом и тегом </Finished>."})
                retries += 1
                if retries > 3:
                    return (msg.content or "Нет ответа") + " </Finished>"
                continue

            logger.info("Final response: %s", msg.content)
            return msg.content
