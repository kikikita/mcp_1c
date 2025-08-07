"""SearchAgent объединяет vLLM-чат и MCP-инструменты.

Использование:
    async with SearchAgent("mcp_server.py") as bot:
        answer = await bot.ask("Привет, мир!")
"""
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
    def __init__(
            self,
            mcp_cmd: str,
            llm_url: str = "http://localhost:8000/v1",
            model: str = "Salesforce/xLAM-2-32b-fc-r"
    ):
        self.mcp = MCP(mcp_cmd)
        self.llm = AsyncOpenAI(base_url=llm_url, api_key=os.getenv("OPENAI_API_KEY", "empty"))
        self.model = model
        self.tools = None  # кеш описания инструментов

    async def __aenter__(self):
        await self.mcp.__aenter__()
        await self.llm.__aenter__()
        self.tools = _mcp_to_openai(await self.mcp.list_tools())
        return self

    async def __aexit__(self, *exc):
        await self.mcp.__aexit__(*exc)
        await self.llm.__aexit__(*exc)

    async def ask(
            self,
            prompt: str,
            system: str | None = None,
            history: List[Dict[str, str]] | None = None,
    ) -> str:
        """Отправляет один запрос LLM, автоматически обслуживая tool-calls."""
        logger.debug("ask called with prompt=%s system=%s history=%s", prompt, system, history)
        msgs: List[Dict[str, str]] = []
        if system:
            msgs.append({"role": "system", "content": system})
        if history:
            msgs.extend(history)
        msgs.append({"role": "user", "content": prompt})
        logger.debug("Initial messages: %s", msgs)

        while True:
            resp = ""
            try:
                resp = await self.llm.chat.completions.create(
                    model=self.model,
                    messages=msgs,
                    tools=self.tools,
                    tool_choice="auto",
                    extra_body={
                        "min_tokens": 5
                    }
                )
                logger.debug("LLM response: %s", resp)
            except Exception as e:
                logger.exception("LLM request failed: %s", e)
                id = msgs[-1]['tool_call_id']
                content = msgs[-1]['content']
                msgs.append({
                    "role": "tool",
                    "tool_call_id": id,
                    "content": content[:len(content) // 2]
                })
                msgs.pop(-2)

            if not resp:
                continue
            msg = resp.choices[0].message

            if msg.tool_calls:
                for call in msg.tool_calls:
                    args = json.loads(call.function.arguments)
                    logger.debug("Calling tool %s with args %s", call.function.name, args)
                    result = await self.mcp.call_tool(call.function.name, args)
                    output = (
                        result.data
                        if result.data is not None
                        else (result.content[0].text if result.content else "")
                    )
                    logger.debug("Tool %s returned %s", call.function.name, output)
                    msgs.append({
                        "role": "tool",
                        "tool_call_id": call.id,
                        "content": json.dumps(output)
                    })
                continue
            if '</Finished>' not in msg.content:
                msgs.append(
                    {"role": "user", "content": "Дай конечный результат с тегом </Finished>, "
                                                "если ты закончил вызов инструментов."})
                continue
            logger.debug("Final response: %s", msg.content)
            return msg.content
