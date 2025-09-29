# Use Python 3.11 slim as base
FROM python:3.11-slim

# Install system dependencies for EvilLimiter
RUN apt-get update && apt-get install -y \
    git \
    net-tools \
    iptables \
    iproute2 \
    iputils-ping \
    python3-dev \
    gcc \
    libc-dev \
    libnetfilter-queue-dev \
    && rm -rf /var/lib/apt/lists/*

# Set working directory
WORKDIR /app

# Set Python unbuffered mode
ENV PYTHONUNBUFFERED=1

# Clone and install EvilLimiter
RUN git clone https://github.com/bitbrute/evillimiter.git /opt/evillimiter && \
    cd /opt/evillimiter && \
    python3 setup.py install

# Copy requirements first for better caching
COPY requirements.txt .

# Install MCP dependencies
RUN pip install --no-cache-dir -r requirements.txt

# Copy the server code
COPY evillimiter_server.py .

# Create non-root user (but EvilLimiter requires root for network ops)
RUN useradd -m -u 1000 mcpuser

# Note: We'll need to run with NET_ADMIN and NET_RAW capabilities
# The server will handle privilege separation internally

# Run the server as root (required for network operations)
# In production, use a privilege separation model
CMD ["python", "evillimiter_server.py"]
