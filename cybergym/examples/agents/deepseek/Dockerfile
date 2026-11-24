FROM node:24-bookworm-slim

RUN apt-get update \
    && apt-get install -y --no-install-recommends \
        bash ca-certificates curl git python3 build-essential file xxd \
    && rm -rf /var/lib/apt/lists/*

ARG DSH_VERSION=0.2.2-rc.5
RUN npm install -g --ignore-scripts --no-audit --no-fund \
        "@deepseek-ai/dsh@${DSH_VERSION}" \
    && dsh --profile headless --help >/dev/null

WORKDIR /workspace
