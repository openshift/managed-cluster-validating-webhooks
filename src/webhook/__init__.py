import flask
from webhook import group_validation
from webhook import metrics
from webhook import namespace_validation
from webhook import regular_user_validation
from webhook import subscription_validation

app = flask.Flask(__name__, instance_relative_config=True)
app.register_blueprint(group_validation.bp)
app.register_blueprint(subscription_validation.bp)
app.register_blueprint(namespace_validation.bp)
app.register_blueprint(regular_user_validation.bp)
app.register_blueprint(metrics.bp)
