from flask import Blueprint, render_template, abort

bp = Blueprint("test", __name__)


@bp.route("/data", methods=["GET"])
def test():
    return '{"id" : "testA", "id" : "testB"}'

@bp.route("/data/first")
def testA():
    return '{"id" : "testA"}'

@bp.route("/data/two")
def testB():
    return '{"id" : "testB"}'