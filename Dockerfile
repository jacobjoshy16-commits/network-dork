FROM python:3.11-slim

ENV PYTHONDONTWRITEBYTECODE=1 \
    PYTHONUNBUFFERED=1 \
    PIP_DISABLE_PIP_VERSION_CHECK=1 \
    UV_PROJECT_ENVIRONMENT=/opt/network-dork/.venv

WORKDIR /opt/network-dork

RUN apt-get update \
    && apt-get install -y --no-install-recommends ca-certificates \
    && rm -rf /var/lib/apt/lists/*

RUN python -m pip install --no-cache-dir uv==0.12.10

COPY pyproject.toml uv.lock README.md LICENSE CONTRIBUTING.md ./
COPY src ./src
RUN uv sync --frozen

ENV PATH="/opt/network-dork/.venv/bin:${PATH}"
WORKDIR /workspace
CMD ["sh", "-lc", "tail -f /dev/null"]
