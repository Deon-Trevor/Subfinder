FROM python:3.11-slim

ENV PYTHONDONTWRITEBYTECODE=1 \
    PYTHONUNBUFFERED=1 \
    PIP_NO_CACHE_DIR=1 \
    CTLOGS_DB_PATH=/data/ctlogs.sqlite3 \
    CTLOGS_ENABLE_LIVE_CT=1 \
    CTLOGS_AUTO_SEED=0

WORKDIR /app

# curl for HEALTHCHECK, ca-certificates for TLS fetches if ingests run at startup
RUN apt-get update && apt-get install -y --no-install-recommends curl ca-certificates && rm -rf /var/lib/apt/lists/*

COPY pyproject.toml README.md SOURCES.md ./
COPY src ./src
RUN pip install --upgrade pip && pip install -e .

# The frontend is static, so it copies in after the install to keep that layer cached
COPY web ./web

# Ensure data dir exists and is writable (DB lives here)
RUN mkdir -p /data && chmod 777 /data

EXPOSE 8000

HEALTHCHECK --interval=10s --timeout=3s --start-period=10s --retries=3 \
  CMD curl -fsS "http://127.0.0.1:8000/health" > /dev/null || exit 1

CMD ["uvicorn", "ctlogs.app:app", "--host", "0.0.0.0", "--port", "8000"]
