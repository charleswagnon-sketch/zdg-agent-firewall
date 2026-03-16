FROM python:3.12-slim AS builder

WORKDIR /app
ENV PYTHONDONTWRITEBYTECODE=1 \
    PYTHONUNBUFFERED=1

RUN apt-get update \
    && apt-get install -y --no-install-recommends build-essential \
    && rm -rf /var/lib/apt/lists/*

COPY requirements.txt ./
RUN python -m venv /opt/venv \
    && /opt/venv/bin/pip install --upgrade pip \
    && /opt/venv/bin/pip install -r requirements.txt

FROM python:3.12-slim AS runtime

LABEL org.opencontainers.image.title="ZDG Agent Firewall" \
      org.opencontainers.image.description="Runtime enforcement control plane for autonomous AI agents." \
      org.opencontainers.image.version="0.1.0"

# Runtime defaults safe for container execution.
# ZDG_DB_PATH and ZDG_MAILDIR_PATH point to the mounted volume (/var/lib/zdg).
# ZDG_FILESYSTEM_ALLOWED_ROOTS is empty so startup validation passes when
# real filesystem execution is gated off (ZDG_REAL_EXEC_FILESYSTEM=false).
# All of these can be overridden via docker-compose environment: or .env.
ENV PYTHONDONTWRITEBYTECODE=1 \
    PYTHONUNBUFFERED=1 \
    PATH="/opt/venv/bin:$PATH" \
    ZDG_DB_PATH=/var/lib/zdg/zdg_firewall.db \
    ZDG_MAILDIR_PATH=/var/lib/zdg/maildir \
    ZDG_WORKSPACE=/var/lib/zdg/workspace \
    ZDG_FILESYSTEM_ALLOWED_ROOTS=[]

RUN useradd --create-home --shell /bin/bash zdg
WORKDIR /app

COPY --from=builder /opt/venv /opt/venv
COPY . /app

RUN mkdir -p /var/lib/zdg /var/lib/zdg/maildir /etc/zdg \
    && chown -R zdg:zdg /app /var/lib/zdg /etc/zdg

USER zdg

VOLUME ["/var/lib/zdg"]

EXPOSE 8000

HEALTHCHECK --interval=30s --timeout=5s --start-period=15s --retries=3 \
  CMD python -c "import urllib.request; urllib.request.urlopen('http://127.0.0.1:8000/health', timeout=3).read()"

CMD ["python", "-m", "uvicorn", "api.app:app", "--host", "0.0.0.0", "--port", "8000"]
