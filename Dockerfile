# Use an official uv image with Python 3.11 pre-installed
# Ref: https://docs.astral.sh/uv/guides/integration/docker/#available-images
FROM ghcr.io/astral-sh/uv:python3.11-bookworm-slim

# Install libpcap-dev for Scapy filtering capabilities
RUN apt-get update && apt-get install -y --no-install-recommends libpcap-dev && rm -rf /var/lib/apt/lists/*

# Set the working directory in the container
WORKDIR /app

# Copy files required for the build process first
COPY pyproject.toml ./
COPY README.md ./

# Install project dependencies and the project itself
RUN uv pip install --system .

# Copy the rest of the application code and necessary files
COPY src/ ./src/
COPY scripts/ ./scripts/
COPY ./.keys/ ./keys/

