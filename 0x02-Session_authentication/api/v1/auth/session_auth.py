#!/usr/bin/env python3
"""Session authentication module.
"""
from api.v1.auth.auth import Auth
from models.user import User
from typing import TypeVar, Optional
import base64
import uuid


class SessionAuth(Auth):
    """Session authentication implementation.
    """
    user_id_by_session_id = {}

    def create_session(self, user_id: str = None) -> Optional[str]:
        """ Creates a session ID for a user_id.

        Args:
            - user_id (str | None): a user ID
        Returns:
            - str: the session ID
            - None: if user_id is invalid
        """
        if user_id is None or type(user_id) is not str:
            return None
        session_id = str(uuid.uuid4())
        self.user_id_by_session_id[session_id] = user_id
        return session_id

    def user_id_for_session_id(self, session_id: str = None) -> str:
        """ Returns a User ID based on a Session ID.
        """
        if session_id is None or type(session_id) is not str:
            return None

        user_id = self.user_id_by_session_id.get(session_id)

        return user_id

    def current_user(self, request=None):
        """ Returns a User instance based on a cookie value.
        """
        if request is None:
            return None
        # retrive session ID; method defined in Auth
        session_id = self.session_cookie(request)
        # print('in /auth/s...', session_id)  # SCAFF
        # retrieve user ID
        user_id = self.user_id_for_session_id(session_id)
        # get User instance
        user = User.get(user_id)

        return user

    def destroy_session(self, request=None):
        """ Deletes the user session, i.e. logout.
        """
        if request is None:
            return False

        session_id = self.session_cookie(request)
        if session_id is None:
            return False

        user_id = self.user_id_for_session_id(session_id)
        if user_id is None:
            return False

        # user has an active session to delete
        del self.user_id_by_session_id[session_id]

        return True
