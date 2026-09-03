FROM python:3.12-slim

WORKDIR /app

RUN apt-get update && apt-get install -y --no-install-recommends \
    build-essential \
    libpq-dev \
    && rm -rf /var/lib/apt/lists/*

COPY . .
ENV PIP_DEFAULT_TIMEOUT=180
ENV PIP_RETRIES=5
RUN pip install --no-cache-dir --default-timeout=180 --retries 5 -r requirements.txt

ENV PYTHONPATH=/app
EXPOSE 8000

CMD ["python", "app/main.py"]
