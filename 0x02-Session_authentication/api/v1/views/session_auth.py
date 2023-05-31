#!/usr/bin/env python3
""" Module for all routes of session authentication.
"""
from api.v1.views import app_views
from flask import abort, jsonify, request, url_for, make_response
from models.user import User
import os
import uuid


@app_views.route(
        '/auth_session/login',
        methods=['POST'],
        strict_slashes=False,
        )
def login() -> str:
    """ Authenticates a user by session and returns their JSON representation.
    """
    user_email = request.form.get('email')
    user_pwd = request.form.get('password')
    if user_email is None or user_email == '':
        # missing or empty email
        return jsonify(dict(error='email missing')), 400
    if user_pwd is None or user_pwd == '':
        return jsonify(dict(error='password missing')), 400

    # get the list of User objects matching the email
    attr = {'email': user_email}
    user_init = User()  # init the DATA dict if not yet
    user_list = User.search(attr)

    if not user_list:
        # no User found
        return jsonify(dict(error="no user found for this email")), 404

    user = None
    for usr in user_list:
        if usr.is_valid_password(user_pwd):
            user = usr
            break

    if user is None:
        # no User password match
        return jsonify(dict(error="wrong password")), 401

    # a User found; create session therefore
    from api.v1.app import auth
    session_id = auth.create_session(user.id)
    # print('in /views/s...', session_id)  # SCAFF

    # make a response object for setting cookie
    resp = make_response(jsonify(user.to_json()))
    sess_cookie_name = os.getenv('SESSION_NAME', '_my_session_id')
    resp.set_cookie(sess_cookie_name, session_id)

    return resp


@app_views.route(
        '/auth_session/logout',
        methods=['DELETE'],
        strict_slashes=False,
        )
def logout():
    """ Destroys user session.
    """
    from api.v1.app import auth
    destroyed = auth.destroy_session(request)

    if not destroyed:
        # session not found
        abort(404)

    return jsonify({}), 200
