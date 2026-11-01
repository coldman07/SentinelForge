FROM python:3.12-slim

ENV PYTHONUNBUFFERED=1 \
    PYTHONDONTWRITEBYTECODE=1

WORKDIR /app
COPY ml/pyproject.toml ./
COPY ml/src/sentinelforge_ueba ./src/sentinelforge_ueba
RUN pip install --no-cache-dir .

CMD ["sentinelforge-ueba"]
