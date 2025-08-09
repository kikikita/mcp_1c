import os
import json, asyncio, re
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


def _shorten(data: Any, limit: int = 500) -> str:
    try:
        txt = json.dumps(_json_ready(data), ensure_ascii=False)
    except Exception:
        txt = repr(data)
    if len(txt) > limit:
        return txt[:limit] + "..."
    return txt


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


DEFAULT_SYSTEM_PROMPT = (
    "Ты работаешь с 1С только через инструменты. Запрещено придумывать данные,"
    " сущности, поля и GUID. Любые факты берутся только из вызванных инструментов;"
    " если данных нет — отвечай 'не найдено'. Все действия выполняй через tool_calls,"
    " не помещай псевдо-вызовы в текстовые сообщения."
)


def _looks_like_pseudo_call(text: str) -> bool:
    if not text:
        return False
    try:
        obj = json.loads(text)
        if isinstance(obj, dict) and (
            obj.get("type") == "function"
            or "tool_name" in obj
            or ("name" in obj and "arguments" in obj)
        ):
            return True
    except Exception:
        pass
    patterns = [r'"type"\s*:\s*"function"', r'"tool_call"', r'"function_call"']
    return any(re.search(p, text) for p in patterns)


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
        base_system = DEFAULT_SYSTEM_PROMPT
        if system:
            base_system = base_system + "\n" + system
        msgs: List[Dict[str, str]] = [{"role": "system", "content": base_system}]
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
                    raw_str = _shorten(result)
                    logger.info("Tool %s raw output %s", call.function.name, raw_str)

                    raw_output = _unwrap_tool_output(result)
                    jsonable_output = _json_ready(raw_output)

                    logger.info("Tool %s returned (normalized) %s", call.function.name, jsonable_output)

                    msgs.append({
                        "role": "tool",
                        "tool_call_id": call.id,
                        "content": json.dumps(jsonable_output, ensure_ascii=False)
                    })
                continue

            if _looks_like_pseudo_call(msg.content or ""):
                logger.warning("Pseudo tool call detected: %s", msg.content)
                msgs.append({"role": "system",
                             "content": "Используй tool_calls для обращения к инструментам и не помещай JSON в текст."})
                continue

            if not msg.content or "</Finished>" not in msg.content:
                msgs.append({"role": "user",
                             "content": "Заверши кратким результатом и тегом </Finished>."})
                retries += 1
                if retries > 3:
                    logger.info("Final response: %s", msg.content)
                    return (msg.content or "Нет ответа") + " </Finished>"
                continue

            logger.info("Final response: %s", msg.content)
            return msg.content
