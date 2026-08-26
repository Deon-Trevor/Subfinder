FROM python:3.11-slim

ENV PYTHONDONTWRITEBYTECODE=1 \
    PYTHONUNBUFFERED=1 \
    PIP_NO_CACHE_DIR=1 \
    CTLOGS_DB_PATH=/data/ctlogs.sqlite3 \
    CTLOGS_CONTROL_DB_PATH=/control/control.sqlite3 \
    CTLOGS_INDEX_READ_ONLY=1

WORKDIR /app

# curl for HEALTHCHECK, ca-certificates for TLS fetches if ingests run at startup
RUN apt-get update && apt-get install -y --no-install-recommends curl ca-certificates && rm -rf /var/lib/apt/lists/*

COPY pyproject.toml ./
RUN pip install --upgrade pip && \
    python -c 'import subprocess, sys, tomllib; dependencies = tomllib.load(open("pyproject.toml", "rb"))["project"]["dependencies"]; subprocess.check_call([sys.executable, "-m", "pip", "install", *dependencies])'

# Application and documentation changes should not invalidate the much slower
# dependency layer above. PYTHONPATH exposes the local package without another
# package-manager or build-isolation pass.
COPY README.md SOURCES.md ./
COPY src ./src
ENV PYTHONPATH=/app/src

# The frontend is static, so it copies in after the install to keep that layer cached
COPY web ./web

# The API reads /data and writes only small admission state under /control.
RUN mkdir -p /data /control && chmod 777 /data /control

EXPOSE 8200

HEALTHCHECK --interval=10s --timeout=3s --start-period=10s --retries=3 \
  CMD curl -fsS "http://127.0.0.1:8200/health" > /dev/null || exit 1

CMD ["uvicorn", "ctlogs.app:app", "--host", "0.0.0.0", "--port", "8200", "--proxy-headers"]
