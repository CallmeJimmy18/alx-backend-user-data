#!/usr/bin/env python3
"""Flask route module"""
from flask import Flask, request, jsonify, make_response, abort
from flask import redirect, url_for
from typing import Dict, Any


from auth import Auth


app = Flask(__name__)
AUTH = Auth()


@app.route('/', methods=['GET'], strict_slashes=False)
def index() -> str:
    return jsonify({"message": "Bienvenue"})


@app.route('/users', methods=['POST'], strict_slashes=False)
def users() -> str:
    """Adds a new user
    """
    email = request.form.get('email')
    password = request.form.get('password')

    try:
        AUTH.register_user(email, password)
        resp_dict = {"email": email, "message": "user created"}
        return jsonify(resp_dict)
    except ValueError:
        return jsonify({"message": "email already registered"}), 400


@app.route('/sessions', methods=['POST'], strict_slashes=False)
def login() -> str:
    """ This logs in a User
    """
    email = request.form.get('email')
    password = request.form.get('password')

    if AUTH.valid_login(email, password):
        session_id = AUTH.create_session(email)
        json_string = {"email": email, "message": "logged in"}
        response = make_response(jsonify(json_string), 200)
        response.set_cookie('session_id', session_id)
        return response
    else:
        abort(401)


@app.route('/sessions', methods=['DELETE'], strict_slashes=False)
def logout() -> str:
    """ This logs a user out
    """
    session_id = request.cookies.get('session_id')

    user = AUTH.get_user_from_session_id(session_id)
    if user is None:
        abort(403)
    else:
        AUTH.destroy_session(user.id)
        return redirect(url_for('index'))


@app.route('/profile', methods=['GET'], strict_slashes=False)
def profile() -> str:
    """ This route gets a users profile
    """
    session_id = request.cookies.get('session_id')

    user = AUTH.get_user_from_session_id(session_id)
    if user is None:
        abort(403)
    else:
        return jsonify({"email": "<user email>"}), 200


@app.route('/reset_password', methods=['POST'], strict_slashes=False)
def get_reset_password_token() -> str:
    """
    """
    email = request.form.get('email')
    reset_token = None

    try:
        reset_token = Auth.get_reset_password_token(email)
    except ValueError:
        reset_token = None

    if reset_token is None:
        abort(403)
    return jsonify({"email": email, "reset_token": reset_token})


@app.route('/reset_password', methods=['PUT'], strict_slashes=False)
def update_password() -> str:
    """ This route updates a users password
    """
    email = request.form.get("email")
    reset_token = request.form.get("reset_token")
    new_password = request.form.get("new_password")
    try:
        AUTH.update_password(reset_token, new_password)
        password_changed = True
    except ValueError:
        password_changed = False

    if not password_changed:
        abort(403)

    return jsonify({"email": email, "message": "Password updated"})


if __name__ == "__main__":
    app.run(host="0.0.0.0", port="5000")
