FROM python:3.12-slim
ENV PYTHONUNBUFFERED=1 PYTHONDONTWRITEBYTECODE=1
WORKDIR /app
COPY assistant/pyproject.toml assistant/README.md ./
COPY assistant/src ./src
RUN pip install --no-cache-dir .
EXPOSE 8090
CMD ["sentinelforge-assistant"]
