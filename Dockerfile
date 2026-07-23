FROM python:3.12-slim

WORKDIR /app

# Install system dependencies
RUN apt-get update && apt-get install -y \
    gcc \
    g++ \
    git \
    clang \
    && rm -rf /var/lib/apt/lists/*

# Copy requirements first (for better caching)
COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt

# Install semgrep
RUN pip install semgrep

# Copy application
COPY . .

# Create necessary directories
RUN mkdir -p app/uploads app/reports app/static/uploads

# Create non-root user
RUN useradd -m -u 1000 vastuser
RUN chown -R vastuser:vastuser /app
USER vastuser

# Health check
HEALTHCHECK --interval=30s --timeout=3s --start-period=5s --retries=3 \
    CMD python -c "import requests; requests.get('http://localhost:5000/health', timeout=2)" || exit 1

EXPOSE 5000
CMD ["gunicorn", "run:app", "--bind", "0.0.0.0:5000", "--workers", "4"]
