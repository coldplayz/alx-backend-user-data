#!/usr/bin/env python3
"""Basic authentication module.
"""
from api.v1.auth.auth import Auth
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
