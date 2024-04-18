#!/usr/bin/env python3
""" BasicAuth """
import re
import base64
import binascii
from .auth import Auth
from typing import Tuple, TypeVar
from api.v1.auth.auth import Auth
from models.user import User


class BasicAuth(Auth):
    """
        Basic authentication class
    """
    def extract_base64_authorization_header(
            self,
            authorization_header: str) -> str:
        """
            Extracts the Base64 part of the Authorization header
        """
        if type(authorization_header) == str:
            patt = r'Basic (?P<token>.+)'
            field_match = re.fullmatch(patt, authorization_header.strip())

            if field_match is not None:
                return field_match.group('token')

        return None

    def decode_base64_authorization_header(
            self,
            base64_authorization_header: str) -> str:
        """
            returns the decoded value of a Base64 string
        """
        if type(base64_authorization_header) == str:
            try:
                checked = base64.b64decode(
                        base64_authorization_header,
                        validate=True,
                        )
                return checked.decode('utf-8')
            except (binascii.Error, UnicodeDecodeError):
                return None

    def extract_user_credentials(
            self,
            decoded_base64_authorization_header: str) -> (str, str):
        """
            returns the user email and password from the Base64 decoded value.
        """
        if type(decoded_base64_authorization_header) == str:
            patt = r'(?P<user>[^:]+):(?P<password>.+)'
            matched = re.fullmatch(
                patt,
                decoded_base64_authorization_header.strip(),
            )
            if matched is not None:
                user = matched.group('user')
                password = matched.group('password')
                return user, password
        return None, None

    def user_object_from_credentials(
            self,
            user_email: str,
            user_pwd: str) -> TypeVar('User'):
        """
            returns the User instance based on his email and password.
        """
        if type(user_email) == str and type(user_pwd) == str:
            try:
                usrs = User.search({'email': user_email})
            except Exception:
                return None
            if len(usrs) <= 0:
                return None
            if usrs[0].is_valid_password(user_pwd):
                return usrs[0]

        return None

    def current_user(self, request=None) -> TypeVar('User'):
        """
            overloads Auth and retrieves the User instance for a request
        """
        auth_header = self.authorization_header(request)
        b64_auth_header = self.extract_base64_authorization_header(auth_header)
        auth_token = self.decode_base64_authorization_header(b64_auth_header)
        email, password = self.extract_user_credentials(auth_token)

        return self.user_object_from_credentials(email, password)
