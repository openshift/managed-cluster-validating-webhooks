# gunicorn config file

access_log_format = '%(h)s %(l)s %(u)s %(t)s "%(r)s" %(s)s %(b)s "%(f)s" "%(a)s" "pid=%(p)s"'
raw_env = [
  'FLASK_APP=webhook'
]
bind = "0.0.0.0:5000"
workers = 5
accesslog = "-"
