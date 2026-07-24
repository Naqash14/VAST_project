import multiprocessing

bind = "0.0.0.0:5000"
workers = 2  # Reduce workers for Railway free tier
worker_class = "sync"
timeout = 120  # Increase timeout to 120 seconds
graceful_timeout = 30
keepalive = 2

accesslog = "-"
errorlog = "-"
loglevel = "info"

preload_app = True
