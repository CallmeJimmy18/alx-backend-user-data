#!/usr/bin/env python3
""" Authentication module """
import bcrypt
import uuid
from db import DB
from sqlalchemy.orm.exc import NoResultFound
from user import User


def _hash_password(password: str) -> bytes:
    """returns bytes that are a salted hash of the input password
    """
    salt = bcrypt.gensalt()
    hashed_password = bcrypt.hashpw(password.encode('utf-8'), salt)

    return hashed_password


def _generate_uuid() -> str:
    """Returns a string representation of a new UUID
    """
    new_uuid = uuid.uuid4()
    return str(new_uuid)


class Auth:
    """Auth class to interact with the authentication database.
    """

    def __init__(self):
        self._db = DB()

    def register_user(self, email: str, password: str) -> User:
        """ This method will register a user with email and password
        """
        try:
            user = self._db.find_user_by(email=email)
            if user is not None:
                raise ValueError("User {} already exists".format(email))

        except NoResultFound:
            hashed_password = _hash_password(password)
            user = self._db.add_user(email, hashed_password)
            return user

    def valid_login(self, email: str, password: str) -> bool:
        """Tries locating the user by email.
            If it exists, check the password with bcrypt.checkpw
        """
        try:
            user = self._db.find_user_by(email=email)
            if user is not None:
                reg_password = user.hashed_password
                if bcrypt.checkpw(password.encode("utf-8"), reg_password):
                    return True
                return False

        except NoResultFound:
            return False

    def create_session(self, email: str) -> str:
        """ find the user corresponding to the email,
            generate a new UUID and
            store it in the database as the user’s session_id

            :param - email
        """
        try:
            user = self._db.find_user_by(email=email)
        except NoResultFound:
            return None
        if user is None:
            return None
        session_id = _generate_uuid()
        self._db.update_user(user.id, session_id=session_id)

        return session_id

    def get_user_from_session_id(self, session_id: str) -> Union[User, None]:
        """ It takes a single session_id string argument and
            returns the corresponding User
        """
        user = None
        if session_id is None:
            return None

        try:
            user = self._db.find_user_by(session_id=session_id)
        except NoResultFound:
            return None

        return user

    def destroy_session(self, user_id: str) -> None:
        """Destroys a session associated with a given user id
        """
        if user_id is None:
            return None
        self._db.update_user(user.id, session_id=None)

    def get_reset_password_token(self, email: str) -> str:
        """Generates a password reset token for a user.
        """
        user = None
        try:
            user = self._db.find_user_by(email=email)
        except NoResultFound:
            return None
        user = None
        if user is None:
            raise ValueError()

        reset_token = _generate_uuid()
        self._db.update_user(user.id, reset_token=reset_token)

        return reset_token

    def update_password(self, reset_token: str, password: str) -> None:
        """ Updates a users password based on the reset_token
        """
        user = None
        try:
            user = self._db.find_user_by(reset_token=reset_token)
        except NoResultFound:
            return None
        user = None
        if user is None:
            raise ValueError()
        new_password = _hash_password(password)
        self._db.update_user(
                user.id,
                hashed_password=new_password,
                reset_token=None,
        )
