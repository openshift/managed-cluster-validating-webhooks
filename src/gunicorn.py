# gunicorn config file
import ssl

access_log_format = '%(h)s %(l)s %(u)s %(t)s "%(r)s" %(s)s %(b)s "%(f)s" "%(a)s" "pid=%(p)s"'
raw_env = [
  'FLASK_APP=webhook',

  'GROUP_VALIDATION_ADMIN_GROUP=osd-sre-admins',
  'GROUP_VALIDATION_PREFIX=osd-sre-',
]
bind="0.0.0.0:5000"
workers=5
accesslog="-"
#cert_reqs = ssl.CERT_REQUIRED