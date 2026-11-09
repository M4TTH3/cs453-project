FROM ubuntu:24.04

ENV DEBIAN_FRONTEND=noninteractive

# 7z + unzip for the NapierOne archives, python3 for the analysis
RUN apt-get update && apt-get install -y --no-install-recommends \
        p7zip-full \
        unzip \
        python3 \
        ca-certificates \
        file \
    && rm -rf /var/lib/apt/lists/*

COPY --from=ghcr.io/astral-sh/uv:0.13.7 /uv /uvx /usr/local/bin/

# venv lives outside /work so it never lands in the bind-mounted repo
ENV UV_PROJECT_ENVIRONMENT=/opt/venv \
    UV_LINK_MODE=copy \
    PATH="/opt/venv/bin:$PATH"

WORKDIR /work
CMD ["bash"]
