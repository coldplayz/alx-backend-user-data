#!/usr/bin/env python3
"""Expiring session authentication module.
"""
from api.v1.auth.auth import Auth
from models.user import User
from typing import TypeVar, Optional
from api.v1.auth.session_auth import SessionAuth
from datetime import datetime, timedelta
import os
import uuid


class SessionExpAuth(SessionAuth):
    """ Implementation of an expirable session.
    """
    user_id_by_session_id = {}

    def __init__(self):
        session_duration = os.getenv('SESSION_DURATION')
        try:
            sess_dur = int(session_duration)
        except (TypeError, ValueError):
            sess_dur = 0
        self.session_duration = sess_dur

    def create_session(self, user_id=None):
        """ Create an expiring session ID.
        """
        session_id = super().create_session(user_id)
        if session_id is None:
            return None

        self.user_id_by_session_id[session_id] = {
                'user_id': user_id,
                'created_at': datetime.now(),
                }
        return session_id

    def user_id_for_session_id(self, session_id=None):
        """ Returns the user ID for session_id.
        """
        if session_id is None or\
                session_id not in self.user_id_by_session_id or\
                'created_at' not in self.user_id_by_session_id[session_id]:
            return None

        # session_id and created_at keys exist at this point

        user_id = self.user_id_by_session_id[session_id].get('user_id')
        if self.session_duration <= 0:
            return user_id

        # retrieve session creation time
        created_at = self.user_id_by_session_id[session_id].get('created_at')

        # create a timedelta object for datetime arithmetic
        td = timedelta(seconds=self.session_duration)
        if (created_at + td) < datetime.now():
            # session expired
            return None

        # else session not expired
        return user_id
