FROM python:3.12-slim

COPY --from=ghcr.io/astral-sh/uv:latest /uv /usr/local/bin/uv


WORKDIR /app

COPY wheels/ /wheels/

# fetch_example_app.py builds the fastapi-guard wheel from the example's own tree and,
# unless LIVE_SMOKE_BASELINE names a released tag, this checkout's guard-core wheel,
# so the example and the libraries are one commit. For a baseline tag guard-core
# resolves from PyPI within that tag's own requirements, as of the tag's commit date
# (baseline-date.txt), and so do the server packages, in one resolution, so a later
# release of any of them cannot leak into the baseline.
RUN uv venv .venv && \
    if [ -f /wheels/baseline-date.txt ]; then \
        uv pip install --python .venv/bin/python \
            --exclude-newer "$(cat /wheels/baseline-date.txt)" \
            gunicorn uvicorn websockets redis guard-agent httpx \
            opentelemetry-sdk opentelemetry-exporter-otlp-proto-http logfire \
            "$(ls /wheels/fastapi_guard-*.whl)[redis,geo,cloud]"; \
    else \
        uv pip install --python .venv/bin/python gunicorn uvicorn websockets redis guard-agent httpx \
            opentelemetry-sdk opentelemetry-exporter-otlp-proto-http logfire && \
        uv pip install --python .venv/bin/python /wheels/fastapi_guard-*.whl \
            "$(ls /wheels/guard_core-*.whl)[redis,geo,cloud]"; \
    fi && \
    .venv/bin/python -c "import guard_core, importlib.metadata as m; import guard; print('guard-core', m.version('guard-core'), guard_core.__file__, 'fastapi-guard', m.version('fastapi-guard'), guard.__file__, 'guard-agent', m.version('guard-agent'), 'redis-py', m.version('redis'))"

RUN mkdir -m 700 /var/lib/guard-cache

COPY app/ /app/app/
COPY gunicorn.conf.py /app/

ENV PATH="/app/.venv/bin:$PATH" \
    PYTHONUNBUFFERED=1 \
    PYTHONDONTWRITEBYTECODE=1

EXPOSE 8000

CMD ["gunicorn", "-c", "gunicorn.conf.py", "app.main:app"]
