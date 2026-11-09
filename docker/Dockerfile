FROM ubuntu:24.04

ENV DEBIAN_FRONTEND=noninteractive

# 7z + unzip for the NapierOne archives; python itself comes from uv
RUN apt-get update && apt-get install -y --no-install-recommends \
        p7zip-full \
        unzip \
        ca-certificates \
        file \
    && rm -rf /var/lib/apt/lists/*

COPY --from=ghcr.io/astral-sh/uv:0.13.7 /uv /uvx /usr/local/bin/

# install the interpreter at build time (as root) so the container can run
# as the host user and still find it
ENV UV_PYTHON=3.14 \
    UV_PYTHON_INSTALL_DIR=/opt/python
RUN uv python install 3.14 && chmod -R a+rX /opt/python

# venv lives in the bind-mounted repo so a host LSP can see site-packages;
# HOME and the cache must be writable by the non-root host user
ENV UV_PROJECT_ENVIRONMENT=/work/.venv \
    UV_LINK_MODE=copy \
    UV_CACHE_DIR=/tmp/uv-cache \
    HOME=/tmp \
    PATH="/work/.venv/bin:$PATH"

WORKDIR /work
CMD ["bash"]
