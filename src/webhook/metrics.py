from flask import Blueprint, Response
import prometheus_client

bp = Blueprint("metrics", __name__)

# send metrics in text format using 0.0.4 version
CONTENT_TYPE_LATEST = str('text/plain; version=0.0.4; charset=utf-8')


@bp.route('/metrics')
def metrics():
    return Response(prometheus_client.generate_latest(), mimetype=CONTENT_TYPE_LATEST)
