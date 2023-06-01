#!/usr/bin/env python3
"""Persisted expiring session authentication module.
"""
from api.v1.auth.auth import Auth
from models.user_session import UserSession
from typing import TypeVar, Optional
from api.v1.auth.session_exp_auth import SessionExpAuth
from datetime import datetime, timedelta
import os
import uuid


class SessionDBAuth(SessionExpAuth):
    """ Implementation of persisted expirable sessions.
    """
    def create_session(self, user_id=None):
        """ Returns an expirinh session ID.
        """
        session_id = super().create_session(user_id)
        if session_id is None:
            return None

        # create instance of UserSession for persistence
        user_session = UserSession(user_id=user_id, session_id=session_id)
        # save the instance; method inherited from Base
        user_session.save()

        return session_id

    def user_id_for_session_id(self, session_id=None):
        """ Returns user ID associated with session_id.
        """
        if session_id is None or type(session_id) is not str:
            return None

        # retrieve the UserSession instance associated with session_id
        attr = {'session_id': session_id}
        user_sessions = UserSession.search(attr)  # Base method
        if not user_sessions:
            # no result; empty list
            return None
        user_session = user_sessions[0]

        # get the user ID from this instance
        user_id = user_session.user_id

        if self.session_duration <= 0:  # SessionExpAuth attr
            return user_id

        # retrieve session creation time
        created_at = user_session.created_at  # Base attribute

        # create a timedelta object for datetime arithmetic
        td = timedelta(seconds=self.session_duration)  # SessionExpAuth attr
        if (created_at + td) < datetime.utcnow():
            # session expired
            return None

        # else session not expired
        return user_id

    def destroy_session(self, request=None):
        """ Destroys the UserSession based on the Session ID.
        """
        session_id = self.session_cookie(request)  # Auth method

        destroyed = self.destroy_session(request)

        if destroyed:
            # retrieve the associated UserSession object and delete it
            attr = {'session_id': session_id}
            user_sessions = UserSession.search(attr)  # Base method
            if not user_sessions:
                # no result; empty list
                return destroyed
            user_session = user_sessions[0]
            user_session.remove()

        return destroyed
