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
def logout() -> wrappers.Response:
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
def profile() -> wrappers.Response:
    """ Returns profile info relating to user with request session ID.
    """
    sess_id = request.cookies.get('session_id')

    # find user with session ID
    user = AUTH.get_user_from_session_id(sess_id)
    if user is None:
        abort(403)

    # User found
    return jsonify({"email": user.email})  # 200 status code by default


@app.route('/reset_password', methods=['POST'], strict_slashes=False)
def get_reset_password_token() -> wrappers.Response:
    """ Provides a token for resetting passwords.
    """
    email = request.form.get('email', None)

    try:
        reset_token = AUTH.get_reset_password_token(email)
        return jsonify({"email": email, "reset_token": reset_token})
    except ValueError:
        # no user with `email` found; forbidden
        abort(403)


@app.route('/reset_password', methods=['PUT'], strict_slashes=False)
def update_password() -> wrappers.Response:
    """ Endpoint for updating passwords based on a valid reset token.
    """
    email = request.form.get('email', None)
    reset_token = request.form.get('reset_token', None)
    new_pwd = request.form.get('new_password', None)

    try:
        AUTH.update_password(reset_token, new_pwd)
        return jsonify({"email": email, "message": "Password updated"})
    except ValueError:
        # invalid token and/or password; abort
        abort(403)


if __name__ == '__main__':
    app.run(host="0.0.0.0", port="5000")
