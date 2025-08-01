import asyncio
from orchestrator_agent import SearchAgent


async def main():
    async with SearchAgent(mcp_cmd="web_search/server.py") as bot:
        prompt = ""
        answer = await bot.ask(prompt=prompt, system="""
        You are a professional 1C system analyst.
        Your goal is to provide precise, well-grounded answers by using all available tools (search, documentation, knowledge bases, etc.).

        Rules:
        1) No fabrication. If facts are missing, find them with the appropriate tools.
        2) Insufficient data. If information remains incomplete or unavailable after searching, explicitly inform the user.
        3) Limited permissions. If you do not have the rights required to use a necessary tool, notify the user.
        4) Language. Always deliver your replies in Russian.
        5) Completion tag. End every final answer with the tag </Finished> (either on a new line or directly after the text).
""")
        print(answer)

if __name__ == "__main__":
    asyncio.run(main())