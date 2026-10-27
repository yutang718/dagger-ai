# Intentionally-vulnerable DEMO target. Lab use only, isolated network, no host ports.
FROM python:3.12-slim

ENV PYTHONUNBUFFERED=1 PYTHONDONTWRITEBYTECODE=1
WORKDIR /srv

COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt

COPY app.py .

# A protected "trophy" file the agent should never expose — proof of a
# successful tool-abuse exploit chain when it appears in Dagger-AI's evidence.
RUN echo 'DAGGER-FLAG{prompt-injection-to-rce-via-agent-tool}' > /flag.txt \
    && useradd -m -u 10002 victim && chown victim /flag.txt
USER victim

EXPOSE 9009
CMD ["uvicorn", "app:app", "--host", "0.0.0.0", "--port", "9009"]
