import os
from typing import Optional, List

import gradio as gr
import logging

from pdf_parser import extract_pdf_text
from orchestrator import SearchAgent
from log_config import setup_logging
from prompt import SYSTEM_PROMPT

setup_logging()
logger = logging.getLogger(__name__)

MAX_TURNS = int(os.getenv("CHAT_HISTORY_TURNS", "5"))


def extract_text(file_path: str) -> str:
    try:
        pages = extract_pdf_text(
            file_path,
            ocr_engine=os.getenv("OCR_ENGINE", "tesseract"),
            ocr_lang=os.getenv("OCR_LANG", "rus+eng"),
            return_format="list",
        )
        return "\n".join(pages)
    except Exception as e:
        logger.exception("Failed to parse document %s: %s", file_path, e)
        return ""


async def chat_fn(message: str, history: list, file: Optional[str]):
    # --- ЛОГИКА ЧАТА НЕ МЕНЯЛАСЬ ---
    logger.info("User message: %s", message)
    text = message
    if file:
        gr.Info("Документ загружен")
        extracted = extract_text(file)
        text += "\n" + extracted

    trimmed_history = history[-MAX_TURNS * 2:] if MAX_TURNS > 0 else history

    formatted_history: List[dict] = []
    for msg in trimmed_history:
        if isinstance(msg, dict):
            role = msg.get("role")
            content = msg.get("content")
        else:
            role = getattr(msg, "role", "")
            content = getattr(msg, "content", "")
        formatted_history.append({"role": role, "content": content})

    async with SearchAgent(
        mcp_cmd=os.getenv("MCP_URL", "http://localhost:9003/mcp/"),
        llm_url=os.getenv("LLM_SERVER_URL", "http://localhost:8000/v1"),
    ) as agent:
        response = await agent.ask(text, system=SYSTEM_PROMPT, history=formatted_history)
        logger.info("Agent response: %s", response)
        return response


def file_badge(file_obj: Optional[gr.File]):
    if file_obj:
        name = os.path.basename(str(file_obj))
        return f'<div class="badge badge-success">✅ Документ загружен: <span>{name}</span></div>'
    return '<div class="badge badge-muted">Файл не загружен</div>'


def main():
    port = int(os.getenv("GRADIO_PORT", "7860"))

    theme = gr.themes.Soft(primary_hue="gray", neutral_hue="gray")

    page_title = "AI – финансист"
    logo_path = os.getenv("LOGO_PATH", "logo.jpg")  # рядом с gradio_app.py

    css = """
    :root {
        --topbar-h: 60px;
        --accent:#E31E24;
        --page-pad:10px;
        --bottom-gap:40px;   /* <-- прозрачный отступ внизу страницы */
    }

    html, body { height: 100%; overflow: hidden; }
    body { margin:0; }
    #app.gradio-container {
        height: 100vh; display:flex; flex-direction:column;
        background:#F7F5E6; color:#2B2B2B;
    }

    /* ---------- ХЭДЕР (логотип слева, заголовок по центру) ---------- */
    #topbar{
        height: var(--topbar-h);
        background:#FFFFFF;
        border-bottom:4px solid var(--accent);
        padding:0 var(--page-pad);
        box-sizing:border-box;
        display:grid;
        grid-template-columns:auto 1fr auto; /* лого | центр | спейсер */
        align-items:center;
        column-gap:12px;
        position:relative;
        z-index:5;
    }
    #topbar .logo-wrap{ display:flex; align-items:center; }
    #topbar .gradio-image, #topbar .image-container, #topbar .image-frame, #topbar .wrap, #topbar .container{
        background:transparent !important; border:none !important; box-shadow:none !important;
        padding:0 !important; margin:0 !important;
    }
    #topbar [aria-label="Download"], #topbar [aria-label="Fullscreen"],
    #topbar [data-testid="image-download"], #topbar [data-testid="image-zoom"]{ display:none !important; }
    .topbar-logo{ height:34px !important; width:auto !important; object-fit:contain; }

    #topbar .title-cell{
        display:flex; align-items:center; justify-content:center;
        width:100%; overflow:hidden;
    }
    #topbar .topbar-title{
        font-weight:700; letter-spacing:0.2px; color:#1F1F1F;
        white-space:nowrap; overflow:hidden; text-overflow:ellipsis;
        font-size: clamp(14px, 2.1vw, 18px);
        max-width:100%;
        text-align:center;
    }
    #topbar .spacer{ width: 150px; } /* баланс ширины с логотипом */

    /* ---------- Основная область = остаток экрана МИНУС bottom-gap ---------- */
    #main-row{
        flex:1 1 auto;
        height: calc(100vh - var(--topbar-h) - var(--bottom-gap));
        padding: var(--page-pad);
        box-sizing:border-box;
        align-items: stretch !important;   /* одинаковая высота колонок */
        gap: var(--page-pad);
        overflow: hidden;                  /* без прокрутки страницы */
        min-height:0;                      /* для корректных вычислений высоты */
    }

    /* Сбрасываем паразитные верхние отступы — заголовки на одном уровне */
    #left-col > .gr-block:first-child,
    #left-col > .gr-column:first-child,
    #chat-col > .gr-block:first-child,
    #chat-col > .gr-column:first-child{ margin-top:0 !important; }
    #left-col .label, #chat-col .label{ margin-top:0 !important; }

    /* Колонки (ширины не меняем) */
    #left-col, #chat-col{ height:100%; min-height:0; }
    #left-col{ width:240px; min-width:220px; max-width:280px; display:flex; }

    /* Левая колонка: дропзона (1fr) + статус (auto) — статус снизу */
    #doc-wrap{
        height:100%; width:100%;
        display:grid; grid-template-rows: 1fr auto;
        gap:8px; padding-bottom: 0;
        box-sizing:border-box; min-height:0;
    }

    /* Дропзона */
    #doc-upload { height:100%; min-height:0; }
    #doc-upload .file-preview, #doc-upload .file-preview-container { display:none !important; }
    #doc-upload [data-testid="file"]{
        height:100% !important; min-height:100% !important;
        border:1px dashed #D6CFA0 !important; border-radius:10px !important;
        background:#FFFEF4 !important; display:flex; align-items:center; justify-content:center;
        text-align:center; padding:10px; box-sizing:border-box;
    }
    #doc-upload [data-testid="file"] *{ font-size:0 !important; line-height:0 !important; }
    #doc-upload [data-testid="file"]::before{
        content:"Перетащите PDF сюда или нажмите для выбора"; font-size:13px; color:#3B3B3B;
    }

    /* Бейдж статуса */
    .badge{
        width:100%; padding:8px 10px; border-radius:8px;
        border:1px solid #E2DCB8; background:#FFFFFF; font-size:13px;
        display:flex; align-items:center; gap:8px; box-sizing:border-box;
    }
    .badge-success{ background:#F2FFF4; border-color:#BFE6C5; color:#1B5E20; }
    .badge-muted{ background:#FDFCF3; color:#6B6B6B; }

    /* Карточки в стиле 1С */
    #app .block, #app .form { background:#FFFFFF; border:1px solid #E2DCB8; border-radius:10px; box-shadow:none; }

    /* ---------- ЧАТ: прокрутка только внутри истории ---------- */
    #chat-col .gr-form{
        margin:0 !important;
        height:100%; min-height:0;
        display:flex; flex-direction:column;
        box-sizing:border-box;
        overflow:hidden;
        gap:8px;
    }
    #chat-col .gr-chatbot{
        flex:1 1 auto;
        min-height:0;
        border:1px solid #E2DCB8; border-radius:10px;
        overflow:auto; /* прокрутка истории внутри окна */
    }

    #app .gr-chatbot .wrap{ border:1px solid #ECE7C8; background:#FAFAF7; }
    #app .gr-chatbot .wrap.user{ background:#FFFEF4; }
    #app textarea, #app .gr-textbox{ background:#FFFEF4; border:1px solid #E2DCB8; }
    #app .gr-button-primary, #app button.primary{ background:#E6E0B8; color:#1F1F1F; border:1px solid #D6CFA0; }

    /* ---------- Прозрачный нижний спейсер (40px) ---------- */
    #bottom-spacer{
        height: var(--bottom-gap);
        min-height: var(--bottom-gap);
        background: transparent;
        pointer-events: none;
        padding: 0;
        margin: 0 var(--page-pad);
        border-radius: 0;
    }
    """

    with gr.Blocks(theme=theme, css=css, elem_id="app", title=page_title) as demo:
        # ---------- ХЭДЕР ----------
        with gr.Row(elem_id="topbar"):
            with gr.Row(elem_classes=["logo-wrap"]):
                gr.Image(
                    value=logo_path,
                    interactive=False,
                    show_label=False,
                    height=34,
                    elem_classes=["topbar-logo"],
                    container=False,
                    show_download_button=False,
                )
            gr.HTML(f'<div class="title-cell"><div class="topbar-title">{page_title}</div></div>')
            gr.HTML('<div class="spacer"></div>')  # баланс ширины для идеального центрирования

        # ---------- ОСНОВНАЯ ОБЛАСТЬ ----------
        with gr.Row(elem_id="main-row", equal_height=True):
            with gr.Column(elem_id="left-col", scale=0, min_width=220):
                with gr.Column(elem_id="doc-wrap"):
                    file_uploader = gr.File(
                        label="Документ",
                        elem_id="doc-upload",
                        file_count="single"
                    )
                    file_status = gr.HTML(file_badge(None))  # индикатор под загрузчиком (всегда виден)

            with gr.Column(elem_id="chat-col", scale=10, min_width=500):
                gr.ChatInterface(
                    chat_fn,
                    additional_inputs=[file_uploader],
                    type="messages",
                )

        # ---------- НИЖНИЙ ПРОЗРАЧНЫЙ СПЕЙСЕР 40PX ----------
        with gr.Row(elem_id="bottom-spacer"):
            gr.HTML("")  # пустая прозрачная строка

        # обновляем бейдж при выборе/очистке файла
        file_uploader.change(fn=file_badge, inputs=file_uploader, outputs=file_status)

    demo.launch(server_name="0.0.0.0", server_port=port)


if __name__ == "__main__":
    main()
