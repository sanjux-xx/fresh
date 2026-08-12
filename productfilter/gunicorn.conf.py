# Gunicorn configuration file
# Prevents workers from being SIGABRT-killed due to idle/slow client connections.
# Kill a worker if it hasn't finished a request within this many seconds.
timeout = 30
# How long to wait for requests on a Keep-Alive connection (should be < timeout).
keepalive = 2
# Number of worker processes (sensible default for small containers).
workers = 2
worker_class = "sync"