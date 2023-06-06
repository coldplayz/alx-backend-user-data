#!/usr/bin/env python3
"""
Integration Tests.
"""
from db import DB
from user import User
from auth import Auth

from sqlalchemy.exc import InvalidRequestError
from sqlalchemy.orm.exc import NoResultFound

import requests

AUTH = Auth()


def register_user(email: str, password: str) -> None:
    """ Test the API for registering new users.
    """
    url = 'http://localhost:5000/users'
    payload = {'email': email, 'password': password}

    r = requests.post(url, data=payload)

    # test invalid credentials case
    if email is None or\
            password is None or\
            not isinstance(email, str) or\
            not isinstance(password, str):
        assert r.json() == {'message': 'email already registered'}
        return

    # test valid registration credentials case
    assert r.json() == {'email': email, 'message': 'user created'}


def log_in_wrong_password(email: str, password: str) -> None:
    """ Test for proper handling of wrong authentication passwords.
    """
    url = 'http://localhost:5000/sessions'
    payload = {'email': email, 'password': password}

    r = requests.post(url, data=payload)

    # 401 status code should be returned
    assert r.status_code == 401


def log_in(email: str, password: str) -> str:
    """ Test authentication with valid credentials, returning the session ID.
    """
    url = 'http://localhost:5000/sessions'
    payload = {'email': email, 'password': password}

    r = requests.post(url, data=payload)

    if email is None or\
            password is None or\
            not isinstance(email, str) or\
            not isinstance(password, str):
        assert r.status_code == 401
        return

    # valid credentials
    assert r.json() == {"email": email, "message": "logged in"}
    return r.cookies.get('session_id')


def profile_unlogged() -> None:
    """ Test expected handling of signed-out/unregistered users.
    """
    url = 'http://localhost:5000/profile'

    r = requests.get(url)

    assert r.status_code == 403


def profile_logged(session_id: str) -> None:
    """ Test getting profile info with logged-in User.
    """
    url = 'http://localhost:5000/profile'
    cookies = {'session_id': session_id}

    r = requests.get(url, cookies=cookies)

    if session_id is None or not isinstance(session_id, str):
        assert r.status_code == 403
        return

    user = AUTH.get_user_from_session_id(session_id)

    # test response
    assert r.status_code == 200
    assert r.json() == {'email': user.email}


def log_out(session_id: str) -> None:
    """ Test for proper log out.
    """
    url = 'http://localhost:5000/sessions'
    cookies = {'session_id': session_id}

    r = requests.delete(url, cookies=cookies)

    if session_id is None or not isinstance(session_id, str):
        assert r.status_code == 403
        return

    # test response for successfull logout
    assert r.json() == {'message': 'Bienvenue'}
    assert r.history[0].is_redirect


def reset_password_token(email: str) -> str:
    """ Test endpoint for resetting tokens, returning the reset token.
    """
    url = 'http://localhost:5000/reset_password'
    payload = {'email': email}

    r = requests.post(url, data=payload)

    if email is None or not isinstance(email, str):
        assert r.status_code == 403
        return

    # email corresponds to a registered User
    sid = r.cookies.get('session_id', None)
    if sid:
        user = AUTH.get_user_from_session_id(sid)
        assert r.json() == {"email": email, "reset_token": user.reset_token}

    assert r.status_code == 200
    return r.json().get('reset_token')


def update_password(email: str, reset_token: str, new_password: str) -> None:
    """ Test endpoint for updating user passwords.
    """
    url = 'http://localhost:5000/reset_password'
    payload = {
            'email': email,
            'reset_token': reset_token,
            'new_password': new_password,
            }

    r = requests.put(url, data=payload)

    if reset_token is None or\
            new_password is None or\
            not isinstance(reset_token, str) or\
            not isinstance(new_password, str):
        assert r.status_code == 403
        return

    assert r.json() == {"email": email, "message": "Password updated"}
    assert r.status_code == 200


EMAIL = "guillaume@holberton.io"
PASSWD = "b4l0u"
NEW_PASSWD = "t4rt1fl3tt3"


if __name__ == "__main__":

    register_user(EMAIL, PASSWD)
    log_in_wrong_password(EMAIL, NEW_PASSWD)
    profile_unlogged()
    session_id = log_in(EMAIL, PASSWD)
    profile_logged(session_id)
    log_out(session_id)
    reset_token = reset_password_token(EMAIL)
    update_password(EMAIL, reset_token, NEW_PASSWD)
    log_in(EMAIL, NEW_PASSWD)
