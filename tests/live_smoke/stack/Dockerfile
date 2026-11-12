FROM python:3.12-slim

COPY --from=ghcr.io/astral-sh/uv:latest /uv /usr/local/bin/uv

ARG GUARD_CORE_SPEC=guard-core==3.17.0

WORKDIR /app

COPY wheels/ /wheels/

# fetch_example_app.py builds both wheels (this checkout's guard-core and the
# fastapi-guard tree the example came from), so the example and the library are one
# commit. Without wheels (LIVE_SMOKE_BASELINE) the released fastapi-guard runs
# against GUARD_CORE_SPEC.
RUN uv venv .venv && \
    uv pip install --python .venv/bin/python gunicorn uvicorn websockets redis guard-agent httpx \
        opentelemetry-sdk opentelemetry-exporter-otlp-proto-http logfire && \
    if ls /wheels/guard_core-*.whl >/dev/null 2>&1; then \
        uv pip install --python .venv/bin/python /wheels/fastapi_guard-*.whl \
            "$(ls /wheels/guard_core-*.whl)[redis,geo,cloud]"; \
    else \
        uv pip install --python .venv/bin/python fastapi-guard "$GUARD_CORE_SPEC"; \
    fi && \
    .venv/bin/python -c "import guard_core, importlib.metadata as m; import guard; print('guard-core', m.version('guard-core'), guard_core.__file__, 'fastapi-guard', m.version('fastapi-guard'), guard.__file__)"

RUN mkdir -m 700 /var/lib/guard-cache

COPY app/ /app/app/
COPY gunicorn.conf.py /app/

ENV PATH="/app/.venv/bin:$PATH" \
    PYTHONUNBUFFERED=1 \
    PYTHONDONTWRITEBYTECODE=1

EXPOSE 8000

CMD ["gunicorn", "-c", "gunicorn.conf.py", "app.main:app"]
