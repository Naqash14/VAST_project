import multiprocessing

bind = "0.0.0.0:5000"
workers = multiprocessing.cpu_count() * 2 + 1
worker_class = "sync"
timeout = 120
keepalive = 2

accesslog = "logs/access.log"
errorlog = "logs/error.log"
loglevel = "info"

preload_app = True
graceful_timeout = 30
