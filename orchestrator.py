"""
SearchAgent объединяет vLLM-чат и MCP-поиск.
Использование:
    async with SearchAgent("web_search/server.py") as bot:
        answer = await bot.ask("Привет, мир!")
"""
import json, asyncio
from openai import AsyncOpenAI
from fastmcp import Client as MCP


def _mcp_to_openai(tools):
    print(tools)
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
        self.llm = AsyncOpenAI(base_url=llm_url, api_key="dummy")
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

    async def ask(self, prompt: str, system: str | None = None) -> str:
        """Отправляет один запрос LLM, автоматически обслуживая tool-calls."""
        msgs = []
        if system:
            msgs.append({"role": "system", "content": system})
        msgs.append({"role": "user", "content": prompt})

        while True:
            resp = ''
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
            except Exception as e:
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
                    result = await self.mcp.call_tool(call.function.name, args)
                    msgs.append({
                        "role": "tool",
                        "tool_call_id": call.id,
                        "content": json.dumps(result[0].text)
                    })
                    print("function_called", result)
                continue
            if '</Finished>' not in msg.content:
                msgs.append(
                    {"role": "user", "content": "Дай конечный результат с тегом </Finished>, "
                                                "если ты закончил вызов инструментов."})
                continue
            return msg.content
