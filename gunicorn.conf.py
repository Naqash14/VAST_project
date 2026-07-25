# Gunicorn configuration for Railway

bind = "0.0.0.0:8080"
workers = 2
worker_class = "sync"
timeout = 120  # Increased from 30 to 120 seconds
graceful_timeout = 30
keepalive = 2

# Logging
accesslog = "-"
errorlog = "-"
loglevel = "info"

# Preload app
preload_app = True

# Max requests before worker restart (prevents memory leaks)
max_requests = 1000
max_requests_jitter = 100
