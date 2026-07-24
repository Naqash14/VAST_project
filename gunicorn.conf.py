import multiprocessing

# Railway free tier optimized
bind = "0.0.0.0:5000"
workers = 1  # Reduce to 1 for free tier
worker_class = "sync"
timeout = 30  # Reduce timeout to restart slow workers faster
graceful_timeout = 10
keepalive = 2

accesslog = "-"
errorlog = "-"
loglevel = "info"

# Preload app for faster startup
preload_app = True

# Max requests before worker restart (prevents memory leaks)
max_requests = 100
max_requests_jitter = 10
