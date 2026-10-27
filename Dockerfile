FROM python:3.12-slim

ENV PYTHONUNBUFFERED=1 \
    PYTHONDONTWRITEBYTECODE=1 \
    DAGGER_DATA_DIR=/data

WORKDIR /srv

RUN apt-get update && apt-get install -y --no-install-recommends curl \
    && rm -rf /var/lib/apt/lists/*

COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt

COPY core ./core
COPY web ./web
COPY tests ./tests

RUN mkdir -p /data && useradd -m -u 10001 dagger && chown -R dagger /data /srv
USER dagger

EXPOSE 8000
HEALTHCHECK --interval=30s --timeout=5s --start-period=12s --retries=3 \
  CMD curl -fsS http://127.0.0.1:8000/api/health || exit 1

CMD ["uvicorn", "core.main:app", "--host", "0.0.0.0", "--port", "8000"]
