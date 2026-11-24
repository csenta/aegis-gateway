# Multi-stage Dockerfile for AegisGateway
FROM python:3.11-slim-bookworm AS builder

WORKDIR /app
COPY requirements.txt .
RUN pip install --no-cache-dir --user -r requirements.txt

# Final Runtime Image
FROM python:3.11-slim-bookworm AS runtime

WORKDIR /app

# Create unprivileged application user
RUN groupadd -r aegis && useradd -r -g aegis -u 10001 aegis \
    && mkdir -p /app/logs && chown -R aegis:aegis /app

# Copy dependencies from builder
COPY --from=builder /root/.local /home/aegis/.local
ENV PATH=/home/aegis/.local/bin:$PATH
ENV PYTHONUNBUFFERED=1

# Copy source code and configuration
COPY --chown=aegis:aegis aegis/ /app/aegis/
COPY --chown=aegis:aegis config/ /app/config/

USER aegis

EXPOSE 8080

HEALTHCHECK --interval=30s --timeout=5s --start-period=5s --retries=3 \
  CMD python3 -c "import urllib.request; urllib.request.urlopen('http://localhost:8080/healthz')" || exit 1

ENTRYPOINT ["python3", "-m", "aegis.cli", "start", "--host", "0.0.0.0", "--port", "8080"]
