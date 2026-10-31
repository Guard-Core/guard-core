ARG PYTHON_VERSION=3.10
FROM python:${PYTHON_VERSION}-slim

RUN apt-get update && apt-get install -y \
    libsodium23 \
    wget \
    build-essential \
    libffi-dev \
    curl \
    git

WORKDIR /app

ENV PIP_NO_CACHE_DIR=false \
    PIP_DISABLE_PIP_VERSION_CHECK=on \
    PIP_DEFAULT_TIMEOUT=10 \
    PYTHONUNBUFFERED=1 \
    PYTHONDONTWRITEBYTECODE=1

RUN pip install uv

COPY pyproject.toml uv.lock README.md /app/
COPY Makefile /app/Makefile

RUN uv sync --locked --extra dev --extra otel --extra logfire
RUN git config --system --add safe.directory /app

ENV PATH="/app/.venv/bin:$PATH"

COPY guard_core/ /app/guard_core/
COPY tests/ /app/tests/
COPY scripts/ /app/scripts/
COPY specs/ /app/specs/
COPY docs/ /app/docs/
COPY CHANGELOG.md /app/CHANGELOG.md
COPY perf_gate/ /app/perf_gate/
COPY .github/scripts/ /app/.github/scripts/

RUN uv pip install --python .venv/bin/python --no-deps -e /app

RUN mkdir -p /app/data/ipinfo
