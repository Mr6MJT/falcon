# Orvex/Falcon API image — FastAPI (uvicorn). WeasyPrint needs the pango/cairo system libs.
FROM python:3.13-slim

ENV PYTHONUNBUFFERED=1 PYTHONPATH=/app
RUN apt-get update && apt-get install -y --no-install-recommends \
        libpango-1.0-0 libpangocairo-1.0-0 libgdk-pixbuf-2.0-0 libcairo2 libffi8 \
    && rm -rf /var/lib/apt/lists/*

WORKDIR /app
RUN pip install --no-cache-dir \
    "fastapi>=0.110" "uvicorn[standard]>=0.29" "sqlalchemy>=2" "psycopg[binary]>=3.1" \
    "alembic>=1.13" "pyjwt>=2.8" "weasyprint>=60" "redis>=5" "celery>=5.4" \
    "cryptography>=42" "tldextract>=5"

COPY alembic.ini ./
COPY packages ./packages
COPY apps/api ./apps/api
COPY migrations ./migrations
COPY scripts ./scripts
COPY infra ./infra

EXPOSE 8000
CMD ["uvicorn", "apps.api.main:app_factory", "--factory", "--host", "0.0.0.0", "--port", "8000"]
