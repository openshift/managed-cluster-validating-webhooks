import flask
import prometheus_client

bp = flask.Blueprint("metrics", __name__)

# send metrics in text format using 0.0.4 version
CONTENT_TYPE_LATEST = str('text/plain; version=0.0.4; charset=utf-8')


@bp.route('/metrics')
def metrics():
    return flask.Response(prometheus_client.generate_latest(),
                          mimetype=CONTENT_TYPE_LATEST)
