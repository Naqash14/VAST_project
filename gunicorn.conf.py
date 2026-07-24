import multiprocessing
import os

# Create logs directory if it doesn't exist
os.makedirs('logs', exist_ok=True)

bind = "0.0.0.0:5000"
workers = multiprocessing.cpu_count() * 2 + 1
worker_class = "sync"
timeout = 120
keepalive = 2

# Use stdout for logs (Railway friendly)
accesslog = "-"
errorlog = "-"
loglevel = "info"

preload_app = True
graceful_timeout = 30
