FROM node:24-bookworm-slim

RUN apt-get update \
    && apt-get install -y --no-install-recommends \
        bash ca-certificates curl git python3 build-essential file xxd \
    && rm -rf /var/lib/apt/lists/*

ARG PI_VERSION=1.6.0
RUN npm install -g --ignore-scripts --no-audit --no-fund \
        "@earendil-works/pi-coding-agent@${PI_VERSION}" \
    && pi --version

WORKDIR /workspace
