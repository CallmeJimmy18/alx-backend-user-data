#!/usr/bin/env python3
"""Module for all Session authentication viewa.
"""
from typing import Tuple
from api.v1.views import app_views
from flask import abort, jsonify, request
from models.user import User
from os import getenv


@app_views.route('/auth_session/login', methods=['POST'], strict_slashes=False)
def login() -> Tuple[str, int]:
    """Posts all user data
    """
    user_email = request.form.get('email')
    if not user_email:
        return jsonify({"error": "email missing"}), 400
    user_password = request.form.get('password')
    if not user_password:
        return jsonify({"error": "password missing"}), 400
    user = User.search({'email': user_email})
    if not user:
        return jsonify({"error": "no user found for this email"}), 404
    for p in user:
        if p.is_valid_password(user_password):
            from api.v1.app import auth
            sess_id = auth.create_session(p.id)
            user_json = jsonify(p.to_json())
            user_json.set_cookie(getenv('SESSION_NAME'), sess_id)
            return user_json
        else:
            return jsonify({"error": "wrong password"}), 401


@app_views.route('/auth_session/logout', methods=['DELETE'],
                 strict_slashes=False)
def logout() -> Tuple[str, int]:
    """Logs out of session
    """
    from api.v1.app import auth
    destroy_session = auth.destroy_session(request)
    if not destroy_session:
        abort(404)
    return jsonify({})
