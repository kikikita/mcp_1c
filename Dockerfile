FROM python:3.12-slim

ENV PYTHONUNBUFFERED=1

# System dependencies for pdf2image and Tesseract OCR
RUN apt-get update && apt-get install -y \
    tesseract-ocr tesseract-ocr-rus poppler-utils \
    && rm -rf /var/lib/apt/lists/*

WORKDIR /app

COPY requirements.txt .
COPY logo.jpg .
RUN pip install --no-cache-dir -r requirements.txt

COPY . .

EXPOSE 7860 9000

CMD ["python", "gradio_app.py"]
