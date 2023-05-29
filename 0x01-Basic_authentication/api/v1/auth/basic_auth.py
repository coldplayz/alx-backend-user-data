#!/usr/bin/env python3
"""Basic authentication module.
"""
from api.v1.auth.auth import Auth
from models.user import User
from typing import TypeVar
import base64


class BasicAuth(Auth):
    """Basic authentication implementation.
    """
    def extract_base64_authorization_header(
            self,
            authorization_header: str,
            ) -> str:
        """Returns the Base64 part of the Authorization header.

        For a Basic Authentication.
        """
        if authorization_header is None or\
                type(authorization_header) is not str:
            return None

        header_parts = authorization_header.split()
        if header_parts[0] != 'Basic':
            # invalid format
            return None

        return header_parts[1]

    def decode_base64_authorization_header(
            self,
            base64_authorization_header: str,
            ) -> str:
        """Returns the decoded value of a Base64 string.

        Args:
            base64_authorization_header (str): a base64 string.

        Returns:
            str: the decoded value of base64_authorization_header.
        """
        if base64_authorization_header is None or\
                type(base64_authorization_header) is not str:
            return None

        # base64_authorization_header is a string
        try:
            return base64.b64decode(
                    base64_authorization_header.encode(),
                    validate=True,
                    ).decode('utf-8')
        except base64.binascii.Error:
            return None

    def extract_user_credentials(
            self,
            decoded_base64_authorization_header: str,
            ) -> (str, str):
        """Returns the user email and password from the Base64 decoded value.
        """
        if decoded_base64_authorization_header is None or\
                type(decoded_base64_authorization_header) is not str:
            return (None, None)

        # decode_base64_authorization_header is a string
        if ':' not in decoded_base64_authorization_header:
            # no credential separator character
            return (None, None)

        # credential separator xter in decoded_base64_authorization_header
        return tuple(decoded_base64_authorization_header.split(':'))

    def user_object_from_credentials(
            self,
            user_email: str,
            user_pwd: str,
            ) -> TypeVar('User'):
        """Returns the User instance based on his email and password.
        """
        if user_email is None or type(user_email) is not str:
            return None
        if user_pwd is None or type(user_pwd) is not str:
            return None

        # get the list of User objects matching the email
        attr = {'email': user_email}
        user_list = User.search(attr)

        user = None
        for usr in user_list:
            if usr.is_valid_password(user_pwd):
                user = usr
                break

        return user  # or None