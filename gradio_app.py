import os
from typing import Optional, List

import gradio as gr
from PIL import Image
from pdf2image import convert_from_path
import pytesseract
import logging

from orchestrator import SearchAgent
from log_config import setup_logging

setup_logging()
logger = logging.getLogger(__name__)

# Число предыдущих сообщений диалога, которые передаются модели.
# Можно задать через переменную окружения CHAT_HISTORY_TURNS.
MAX_TURNS = int(os.getenv("CHAT_HISTORY_TURNS", "5"))


def extract_text(file_path: str) -> str:
    ext = os.path.splitext(file_path)[1].lower()
    if ext == '.pdf':
        pages = convert_from_path(file_path)
        return "\n".join(pytesseract.image_to_string(p, lang='rus') for p in pages)
    else:
        img = Image.open(file_path)
        return pytesseract.image_to_string(img, lang='rus')


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
