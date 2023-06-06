#!/usr/bin/env python3
""" Flask app.
"""
from flask import (
        Flask, jsonify, request, abort, wrappers,
        make_response, redirect, url_for)
from typing import Tuple, Union
from auth import Auth
from sqlalchemy.orm.exc import NoResultFound

AUTH = Auth()

app = Flask(__name__)


@app.route('/', methods=['GET', 'DELETE'], strict_slashes=False)
def index() -> wrappers.Response:
    """ Produces test output.
    """
    return jsonify({'message': 'Bienvenue'})


@app.route('/users', methods=['POST'], strict_slashes=False)
def users() -> Union[wrappers.Response, Tuple[wrappers.Response, int]]:
    """ Endpoint for registering new users.
    """
    email = request.form.get('email', None)
    pwd = request.form.get('password')

    if email is None or pwd is None:
        abort(400)

    # email and password strings present
    try:
        new_user = AUTH.register_user(email, pwd)
        return jsonify({
            "email": email,
            "message": "user created",
            })
    except ValueError:
        return jsonify({"message": "email already registered"}), 400


@app.route('/sessions', methods=['POST'], strict_slashes=False)
def login() -> wrappers.Response:
    """ Associate a session ID with a valid User.
    """
    # retrieve login credentials
    email = request.form.get('email', None)
    pwd = request.form.get('password')

    if email is None or pwd is None:
        # unauthorized
        abort(401)

    if not AUTH.valid_login(email, pwd):
        # invalid credentials
        abort(401)

    # valid credentials; create new session for user
    sess_id = AUTH.create_session(email)

    # set this session ID in cookie
    resp = make_response(jsonify({"email": email, "message": "logged in"}))
    resp.set_cookie('session_id', sess_id)

    return resp


@app.route('/sessions', methods=['DELETE'], strict_slashes=False)
def logout() -> None:
    """ Destroys the user's session and redirects to index.
    """
    # retrieve session cookie from request
    sess_id = request.cookies.get('session_id')

    # find user with session ID
    user = AUTH.get_user_from_session_id(sess_id)
    if user is None:
        abort(403)

    # User object found; destroy its session
    AUTH.destroy_session(user.id)
    # redirect to index
    return redirect(url_for('index'))


@app.route('/profile', strict_slashes=False)
def profile():
    """ Returns profile info relating to user with request session ID.
    """
    sess_id = request.cookies.get('session_id')

    # find user with session ID
    user = AUTH.get_user_from_session_id(sess_id)
    if user is None:
        abort(403)

    # User found
    return jsonify({"email": user.email})  # 200 status code by default


if __name__ == '__main__':
    app.run(host="0.0.0.0", port="5000")
