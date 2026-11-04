FROM python:3.12-slim

WORKDIR /app
COPY correlation/pyproject.toml correlation/README.md ./
COPY correlation/src ./src
RUN pip install --no-cache-dir .

CMD ["sentinelforge-m6-worker"]
