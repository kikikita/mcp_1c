import os
import json, asyncio
from typing import List, Dict
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

        # Простейший backoff, чтобы не зациклиться
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
                    output = (
                        result.data
                        if result.data is not None
                        else (result.content[0].text if result.content else "")
                    )
                    logger.info("Tool %s returned %s", call.function.name, output)
                    msgs.append({
                        "role": "tool",
                        "tool_call_id": call.id,
                        "content": json.dumps(output, ensure_ascii=False)
                    })
                continue

            if not msg.content or "</Finished>" not in msg.content:
                # Мягкое добивание финального ответа
                msgs.append({"role": "user",
                             "content": "Заверши кратким результатом и тегом </Finished>."})
                retries += 1
                if retries > 3:
                    return (msg.content or "Нет ответа") + " </Finished>"
                continue

            logger.info("Final response: %s", msg.content)
            return msg.content
