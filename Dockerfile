# Multi-stage Docker build for Security Data Fabric
# Stage 1: Builder
FROM python:3.11-slim AS builder

# Set build arguments
ARG BUILD_DATE
ARG VERSION=1.0.0

# Install build dependencies
RUN apt-get update && apt-get install -y --no-install-recommends \
    gcc \
    g++ \
    libpq-dev \
    && rm -rf /var/lib/apt/lists/*

# Create virtual environment
RUN python -m venv /opt/venv
ENV PATH="/opt/venv/bin:$PATH"

# Copy requirements and install dependencies
COPY requirements.txt .
RUN pip install --no-cache-dir --upgrade pip setuptools wheel && \
    pip install --no-cache-dir -r requirements.txt

# Stage 2: Runtime
FROM python:3.11-slim

# Add metadata labels
LABEL org.opencontainers.image.title="Security Data Fabric" \
      org.opencontainers.image.description="Unified Security Data Platform with Medallion Architecture" \
      org.opencontainers.image.version="${VERSION}" \
      org.opencontainers.image.created="${BUILD_DATE}" \
      org.opencontainers.image.vendor="Security Team" \
      maintainer="security-team@example.com"

# Install runtime dependencies only
RUN apt-get update && apt-get install -y --no-install-recommends \
    libpq5 \
    curl \
    && rm -rf /var/lib/apt/lists/* \
    && apt-get clean

# Create non-root user with specific UID/GID
RUN groupadd -r -g 1000 appuser && \
    useradd -r -u 1000 -g appuser -m -s /sbin/nologin appuser

# Copy virtual environment from builder
COPY --from=builder --chown=appuser:appuser /opt/venv /opt/venv

# Set environment variables
ENV PATH="/opt/venv/bin:$PATH" \
    PYTHONUNBUFFERED=1 \
    PYTHONDONTWRITEBYTECODE=1 \
    PYTHONPATH=/app \
    PIP_NO_CACHE_DIR=1 \
    PIP_DISABLE_PIP_VERSION_CHECK=1

# Create application directory structure
RUN mkdir -p /app /app/logs /app/tmp && \
    chown -R appuser:appuser /app

# Set working directory
WORKDIR /app

# Copy application code
COPY --chown=appuser:appuser src/ ./src/
COPY --chown=appuser:appuser pyproject.toml ./

# Switch to non-root user
USER appuser

# Expose port
EXPOSE 8000

# Health check
HEALTHCHECK --interval=30s --timeout=10s --start-period=40s --retries=3 \
    CMD curl -f http://localhost:8000/health || exit 1

# Drop all capabilities (security hardening)
# Note: This is handled by docker-compose.yml or runtime configuration

# Start application with Uvicorn
CMD ["uvicorn", "src.api.main:app", \
     "--host", "0.0.0.0", \
     "--port", "8000", \
     "--workers", "4", \
     "--loop", "uvloop", \
     "--log-level", "info", \
     "--access-log", \
     "--proxy-headers", \
     "--forwarded-allow-ips", "*"]
