# Throwaway capture sandbox for the top-100 MCP survey.
#
# Why a container: capturing a server's tool surface means *launching* it, which
# runs the package's install/postinstall + boot code. Doing that for ~100
# unpinned `npx -y` / `uvx` packages on a workstation is precisely the supply-
# chain risk Scrutineer warns about. Here it runs as a non-root user in a
# disposable container with only the output dir mounted writable.
#
# Build context = the corpus dir (parent), so we can COPY capture_tools.py.
FROM node:22-slim

RUN apt-get update && apt-get install -y --no-install-recommends \
        python3 python3-pip ca-certificates curl git \
    && rm -rf /var/lib/apt/lists/* \
    && pip install --no-cache-dir --break-system-packages uv

# uvx/uv on PATH; npx ships with node. Caches under /tmp owned by the `node`
# user (uid 1000, ships with the node image) — we run unprivileged.
ENV NPM_CONFIG_CACHE=/tmp/.npm \
    UV_CACHE_DIR=/tmp/.uv

COPY capture_tools.py /work/capture_tools.py
COPY top100/docker_capture_entry.sh /work/entry.sh
RUN chmod +x /work/entry.sh && mkdir -p /out /tmp/.npm /tmp/.uv \
    && chown -R node:node /work /out /tmp/.npm /tmp/.uv

USER node
WORKDIR /work
ENTRYPOINT ["/work/entry.sh"]
