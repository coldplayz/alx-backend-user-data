#!/usr/bin/env python3
"""Authentication base class.
"""
from flask import request
from typing import List, TypeVar


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
        if s_path not in excluded_paths:
            return True
        return False

    def authorization_header(self, request=None) -> str:
        """Returns a string.
        """
        if request is None:
            return None

        # check for Authorization header key
        auth_obj = request.headers.get('authorization')
        print(auth_obj)
        if auth_obj is None:
            return None
        return auth_obj

    def current_user(self, request=None) -> TypeVar('User'):
        """Returns a User object.
        """
        # TODO: IiF-3: implement in full
        return None
