#!/usr/bin/env python3
""" Auth """
from flask import request
from typing import List, TypeVar


class Auth():
    """
        Class to manage the API authentication
    """
    def require_auth(self, path: str, excluded_paths: List[str]) -> bool:
        """
            :param - path
            :param - excluded_paths
        """
        if path is None:
            return True

        if excluded_paths is None or len(excluded_paths) == 0:
            return True

        path = path.rstrip('/')
        excluded_paths = [p.rstrip('/') for p in excluded_paths]

        if path in excluded_paths:
            return False

        for excluded_path in excluded_paths:
            if path.startswith(excluded_path):
                return False

        return True

    def authorization_header(self, request=None) -> str:
        """
            :param - request
        """
        if request is None:
            return None

        headers = request.headers

        if 'Authorization' in headers:
            auth_header = headers['Authorization']
            return auth_header

        return None

    def current_user(self, request=None) -> TypeVar('User'):
        """
            :param - request
        """
        return None
