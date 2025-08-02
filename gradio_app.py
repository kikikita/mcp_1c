import os
import asyncio
from typing import Optional

import gradio as gr
from PIL import Image
from pdf2image import convert_from_path
import pytesseract

from orchestrator import SearchAgent


def extract_text(file_path: str) -> str:
    ext = os.path.splitext(file_path)[1].lower()
    if ext == '.pdf':
        pages = convert_from_path(file_path)
        return "\n".join(pytesseract.image_to_string(p, lang='rus') for p in pages)
    else:
        img = Image.open(file_path)
        return pytesseract.image_to_string(img, lang='rus')


async def chat_fn(message: str, history: list, file: Optional[str]):
    text = message
    if file:
        text += "\n" + extract_text(file)
    async with SearchAgent(mcp_cmd=os.getenv('MCP_URL', 'http://localhost:9000')) as agent:
        return await agent.ask(text)


def main():
    with gr.Blocks() as demo:
        gr.Markdown("# Ассистент бухгалтера")
        chatbot = gr.ChatInterface(
            chat_fn,
            additional_inputs=[gr.File(label='Документ')],
            type="messages",
        )
    demo.launch(server_name="0.0.0.0")


if __name__ == '__main__':
    main()
