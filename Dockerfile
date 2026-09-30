# One container: FastAPI serves the API at /api/* and the statically exported UI at /.

FROM node:22-alpine AS ui
WORKDIR /ui
COPY frontend/package.json frontend/package-lock.json ./
RUN npm ci
COPY frontend/ ./
ENV NEXT_OUTPUT=export NEXT_TELEMETRY_DISABLED=1
RUN npm run build

FROM python:3.12-slim
COPY --from=ghcr.io/astral-sh/uv:0.10 /uv /usr/local/bin/uv
WORKDIR /app
ENV UV_COMPILE_BYTECODE=1 UV_LINK_MODE=copy
COPY backend/pyproject.toml backend/uv.lock ./
RUN uv sync --frozen --no-dev --no-install-project
COPY backend/src ./src
RUN uv sync --frozen --no-dev
COPY --from=ui /ui/out ./ui
RUN useradd --create-home --uid 10001 app
USER app
ENV PHISHLENS_STATIC_DIR=/app/ui PORT=8000
EXPOSE 8000
HEALTHCHECK --interval=30s --timeout=5s CMD python -c "import urllib.request,os; urllib.request.urlopen(f'http://127.0.0.1:{os.environ[\"PORT\"]}/api/health')"
# Client addresses are derived from X-Forwarded-For by the app itself (PHISHLENS_PROXY_HOPS),
# so uvicorn's own proxy-header handling stays off.
CMD ["sh", "-c", "exec /app/.venv/bin/uvicorn phishlens.api:app --host 0.0.0.0 --port \"$PORT\" --no-proxy-headers"]
