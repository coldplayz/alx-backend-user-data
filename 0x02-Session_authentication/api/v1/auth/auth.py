#!/usr/bin/env python3
"""Authentication base class.
"""
from flask import request
from typing import List, TypeVar
import os


class Auth:
    """Abstract class for authentication.
    """
    def require_auth(self, path: str, excluded_paths: List[str]) -> bool:
        """Returns True if path is not in excluded_paths; Flase otherwise.
        """
        if path is None or not excluded_paths:
            return True

        # it's assumed excluded_paths has strings ending with slash
        # ensure path ends with a slash always
        s_path = (path + '/') if not path.endswith('/') else path
        """
        if s_path not in excluded_paths:
            return True
        """

        for excluded_path in excluded_paths:
            if '*' in excluded_path:
                start = excluded_path.split('*')[0]
                if s_path.startswith(start):
                    return False
            if s_path == excluded_path:
                return False
        return True

    def authorization_header(self, request=None) -> str:
        """Returns a string.
        """
        if request is None:
            return None

        # check for Authorization header key
        auth_obj = request.headers.get('authorization')
        if auth_obj is None:
            return None
        return auth_obj

    def current_user(self, request=None) -> TypeVar('User'):
        """Returns a User object.
        """
        # to be overriden by concrete/sub- classes
        return None

    def session_cookie(self, request=None):
        """ Returns the session cookie value from a request.
        """
        if request is None:
            return None

        cookie_name = os.getenv('SESSION_NAME', '_my_session_id')

        session_id = request.cookies.get(cookie_name)
        # print('in /auth/au...', session_id)  # SCAFF

        return session_id
