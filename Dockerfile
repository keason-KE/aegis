FROM python:3.12-slim AS gateway
ENV PYTHONDONTWRITEBYTECODE=1 PYTHONUNBUFFERED=1
WORKDIR /app
COPY pyproject.toml README.md ./
COPY aegis ./aegis
RUN pip install --no-cache-dir . && useradd --uid 10001 --create-home aegis && mkdir /data && chown aegis:aegis /data
USER 10001:10001
CMD ["python", "-m", "aegis.container_gateway"]

FROM python:3.12-slim AS agent
ENV PYTHONDONTWRITEBYTECODE=1 PYTHONUNBUFFERED=1
WORKDIR /agent
COPY lab/probe.py /agent/probe.py
USER 10002:10002
CMD ["python", "/agent/probe.py"]
