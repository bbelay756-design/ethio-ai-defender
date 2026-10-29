# ETHIO-AI Defender - OPS-02: Containerized Ghidra Headless Sidecar Service
#
# Hardened, non-root isolated container running Ghidra headless analysis.
# Samples are mounted read-only (:ro). Zero live binary execution.

FROM eclipse-temurin:17-jdk-jammy AS base

# Prevent interactive prompts during build
ENV DEBIAN_FRONTEND=noninteractive
ENV GHIDRA_VERSION=11.1.2
ENV GHIDRA_DATE=20240709
ENV GHIDRA_HOME=/opt/ghidra
ENV PATH="${GHIDRA_HOME}/support:${PATH}"

# Install Python 3, pip, curl, unzip, ca-certificates
RUN apt-get update && apt-get install -y --no-install-recommends \
    python3 \
    python3-pip \
    curl \
    unzip \
    ca-certificates \
    && rm -rf /var/lib/apt/lists/*

# Install minimal FastAPI & Uvicorn for internal sidecar RPC
RUN pip3 install --no-cache-dir \
    fastapi==0.110.0 \
    uvicorn==0.28.0 \
    pydantic==2.6.4

# Create non-root system user and group (UID 10001)
RUN groupadd -g 10001 ghidra && \
    useradd -u 10001 -g ghidra -m -s /bin/bash ghidra

# Setup directory structure with strict permissions
WORKDIR /app
RUN mkdir -p /app/scripts /opt/ghidra /samples /tmp/workspace && \
    chown -R ghidra:ghidra /app /opt/ghidra /samples /tmp/workspace

# Copy extraction script and sidecar server
COPY ghidra_scripts/dump_program_info.py /app/scripts/dump_program_info.py
COPY docker/ghidra-sidecar/sidecar_server.py /app/sidecar_server.py

# Set executable permissions
RUN chmod +x /app/sidecar_server.py

# Switch to unprivileged non-root user
USER ghidra

# Default environment
ENV SAMPLES_DIR=/samples
ENV WORKSPACE_DIR=/tmp/workspace
ENV GHIDRA_SIDECAR_PORT=8089
ENV PYTHONUNBUFFERED=1

EXPOSE 8089

# Healthcheck
HEALTHCHECK --interval=30s --timeout=10s --start-period=5s --retries=3 \
    CMD python3 -c "import urllib.request; urllib.request.urlopen('http://127.0.0.1:8089/health')" || exit 1

ENTRYPOINT ["python3", "/app/sidecar_server.py"]
