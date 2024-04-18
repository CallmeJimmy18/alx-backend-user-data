#!/usr/bin/env python3
""" SessionAuth """
import uuid
from api.v1.auth.auth import Auth
from models.user import User


class SessionAuth(Auth):
    """ Creates new authentication mechanism """
    user_id_by_session_id = {}

    def create_session(self, user_id: str = None) -> str:
        """ This fuction creates a session """
        if type(user_id) == str:
            sess_id = str(uuid.uuid4())
            self.user_id_by_session_id[sess_id] = user_id

            return sess_id

        return None

    def user_id_for_session_id(self, session_id: str = None) -> str:
        """returns a User ID based on a Session ID
        """
        if type(session_id) == str:
            return self.user_id_by_session_id.get(session_id)

        return None

    def current_user(self, request=None):
        """(overload) that returns a User instance based on a cookie value
        """
        sess_id = self.session_cookie(request)
        userid = self.user_id_for_session_id(sess_id)

        return User.get(userid)

    def destroy_session(self, request=None):
        """Deletes the user session / logout
        """
        if request:
            sess_id = self.session_cookie(request)
            if sess_id:
                user_id = self.user_id_for_session_id(sess_id)
                if user_id:
                    del self.user_id_for_session_id[sess_id]
                    return True

        return False
