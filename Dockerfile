# Multi-platform universal Dockerfile for AEGIS Security Framework
FROM python:3.11-slim

LABEL maintainer="Belalingbi Steve <https://github.com/Belalingbi/>"
LABEL description="AEGIS Security Framework - Universal Cybersecurity CLI/TUI"

# Install system dependencies for Scapy, network diagnostics & compilation
RUN apt-get update && apt-get install -y --no-install-recommends \
    libpcap-dev \
    tcpdump \
    net-tools \
    iputils-ping \
    git \
    gcc \
    && rm -rf /var/lib/apt/lists/*

WORKDIR /app

# Copy dependency specifications first for caching
COPY requirements.txt .
RUN pip install --no-cache-dir --upgrade pip && \
    pip install --no-cache-dir -r requirements.txt

# Copy AEGIS source code
COPY . .
RUN pip install --no-cache-dir -e .

# Set up reports directory
RUN mkdir -p aegis_reports && chmod 777 aegis_reports

# Default volume for persistent reports and logs
VOLUME ["/app/aegis_reports"]

# Default entrypoint
ENTRYPOINT ["aegis"]
CMD ["--help"]
