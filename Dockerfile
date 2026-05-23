# syntax=docker/dockerfile:1.6
FROM eclipse-temurin:21-jdk AS ghidra
ARG GHIDRA_VERSION=12.1
ARG GHIDRA_ZIP_URL=https://github.com/NationalSecurityAgency/ghidra/releases/download/Ghidra_${GHIDRA_VERSION}_build/ghidra_${GHIDRA_VERSION}_PUBLIC_20260513.zip

RUN apt-get update && apt-get install -y --no-install-recommends \
    curl unzip git python3 python3-pip python3-venv python3-dev ca-certificates \
    libxml2-dev libxslt1-dev g++ \
    && rm -rf /var/lib/apt/lists/*

WORKDIR /opt
RUN curl -sL "${GHIDRA_ZIP_URL}" -o ghidra.zip \
    && unzip -q ghidra.zip \
    && mv ghidra_${GHIDRA_VERSION}_PUBLIC ghidra \
    && rm ghidra.zip

ENV GHIDRA_HOME=/opt/ghidra
ENV PATH="${GHIDRA_HOME}/support:${PATH}"

# Install ghidra-m32r extension at the merged SHA from Spec B
RUN git clone https://github.com/RcusStackwalker/ghidra-m32r.git /tmp/ghidra-m32r \
    && cd /tmp/ghidra-m32r \
    && git checkout bb40b00a17c5fb9580eb212d97fda5afe2c56740 \
    && mkdir -p ${GHIDRA_HOME}/Ghidra/Processors/M32R \
    && cp Module.manifest ${GHIDRA_HOME}/Ghidra/Processors/M32R/ \
    && cp -r data ${GHIDRA_HOME}/Ghidra/Processors/M32R/ \
    && rm -rf /tmp/ghidra-m32r

WORKDIR /work
COPY pyproject.toml ./
COPY rom_analyzer ./rom_analyzer
COPY reference ./reference
# ROMs are not part of the image (CLAUDE.md: No ROM distribution).
# Users mount a ROM at runtime: `docker run -v /local/rom.bin:/work/roms/rom.bin ...`
RUN mkdir -p /work/roms \
    && CFLAGS="-Wno-error=incompatible-pointer-types" pip install --break-system-packages -e ".[dev]"

ENTRYPOINT ["rom-analyzer"]
