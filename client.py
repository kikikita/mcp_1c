import asyncio
import os
import logging
from orchestrator import SearchAgent
from log_config import setup_logging
from prompt import SYSTEM_PROMPT

setup_logging()
logger = logging.getLogger(__name__)


async def main():
    async with SearchAgent(
        mcp_cmd="mcp_server.py",
        llm_url=os.getenv("LLM_SERVER_URL", "http://localhost:8000/v1"),
    ) as bot:
        prompt = ""
        answer = await bot.ask(prompt=prompt, system=SYSTEM_PROMPT)
        logger.info("Answer: %s", answer)

if __name__ == "__main__":
    asyncio.run(main())
