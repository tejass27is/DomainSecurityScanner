FROM python:3.12-slim

WORKDIR /app

RUN apt-get update && apt-get install -y --no-install-recommends \
    build-essential \
    git \
    libpq-dev \
    && rm -rf /var/lib/apt/lists/*

COPY . .
ENV PIP_DEFAULT_TIMEOUT=180
ENV PIP_RETRIES=5
RUN pip install --no-cache-dir --default-timeout=180 --retries 5 -r requirements.txt

RUN python -m venv /opt/prowler \
    && /opt/prowler/bin/pip install --no-cache-dir --default-timeout=180 --retries 5 prowler==5.44.0

ENV PYTHONPATH=/app
ENV PROWLER_EXECUTABLE=/opt/prowler/bin/prowler
ENV PROWLER_PYTHON_EXECUTABLE=/opt/prowler/bin/python
RUN addgroup --system app && adduser --system --ingroup app app \
    && mkdir -p /app/storage/vapt-attachments \
    && chown -R app:app /app
USER app
ENV HOME=/tmp
EXPOSE 8000

CMD ["python", "app/main.py"]
