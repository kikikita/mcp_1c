import os
from typing import Optional, List

import gradio as gr
import logging

from pdf_parser import extract_pdf_text

from orchestrator import SearchAgent
from log_config import setup_logging

setup_logging()
logger = logging.getLogger(__name__)

# Число предыдущих сообщений диалога, которые передаются модели.
# Можно задать через переменную окружения CHAT_HISTORY_TURNS.
MAX_TURNS = int(os.getenv("CHAT_HISTORY_TURNS", "5"))


def extract_text(file_path: str) -> str:
    try:
        pages = extract_pdf_text(
            file_path,
            ocr_engine="paddle",
            ocr_lang="ru",
            return_format="list",
        )
        return "\n".join(pages)
    except Exception as e:
        logger.exception("Failed to parse document %s: %s", file_path, e)
        return ""


async def chat_fn(message: str, history: list, file: Optional[str]):
    """Основная функция чата Gradio.

    Parameters:
        message: Текст очередного сообщения пользователя.
        history: История переписки в формате gr.ChatMessage.
        file:   Необязательный файл с документом, который необходимо распознать.
    """

    logger.info("User message: %s", message)
    text = message
    if file:
        gr.Info("Документ загружен")
        extracted = extract_text(file)
        text += "\n" + extracted

    # Ограничиваем длину истории, чтобы не переполнять контекст окна модели.
    trimmed_history = history[-MAX_TURNS * 2:] if MAX_TURNS > 0 else history

    formatted_history: List[dict] = []
    for msg in trimmed_history:
        if isinstance(msg, dict):
            role = msg.get("role")
            content = msg.get("content")
        else:  # поддержка объектов gr.ChatMessage
            role = getattr(msg, "role", "")
            content = getattr(msg, "content", "")
        formatted_history.append({"role": role, "content": content})

    async with SearchAgent(
        mcp_cmd=os.getenv("MCP_URL", "http://localhost:9003/mcp/"),
        llm_url=os.getenv("LLM_SERVER_URL", "http://localhost:8000/v1"),
    ) as agent:
        response = await agent.ask(text, history=formatted_history)
        logger.info("Agent response: %s", response)
        return response


def main():
    port = int(os.getenv("GRADIO_PORT", "7860"))
    with gr.Blocks() as demo:
        gr.Markdown("# Ассистент бухгалтера")
        gr.ChatInterface(
            chat_fn,
            additional_inputs=[gr.File(label="Документ")],
            type="messages",
        )
    demo.launch(server_name="0.0.0.0", server_port=port)


if __name__ == '__main__':
    main()
