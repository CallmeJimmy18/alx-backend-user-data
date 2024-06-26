#!/usr/bin/env python3
"""DB module
"""
from sqlalchemy import create_engine, tuple_
from sqlalchemy.ext.declarative import declarative_base
from sqlalchemy.orm.exc import NoResultFound
from sqlalchemy.exc import InvalidRequestError
from sqlalchemy.orm import sessionmaker
from sqlalchemy.orm.session import Session
from typing import Optional

from user import Base, User


class DB:
    """DB class
    """

    def __init__(self) -> None:
        """Initialize a new DB instance
        """
        self._engine = create_engine("sqlite:///a.db", echo=True)
        Base.metadata.drop_all(self._engine)
        Base.metadata.create_all(self._engine)
        self.__session = None

    @property
    def _session(self) -> Session:
        """Memoized session object
        """
        if self.__session is None:
            DBSession = sessionmaker(bind=self._engine)
            self.__session = DBSession()
        return self.__session

    def add_user(self, email: str, hashed_password: str) -> User:
        """ Saves the user to the database.
        """
        try:
            new_user = User(email=email, hashed_password=hashed_password)
            self._session.add(new_user)
            self._session.commit()
        except Exception:
            self._session.rollback()
            new_user = None

        return new_user

    def find_user_by(self, **kwargs) -> User:
        """This method takes in arbitrary keyword arguments
           and returns the first row found in the users
        """
        keys, values = [], []
        for key, value in kwargs.items():
            if hasattr(User, key):
                keys.append(getattr(User, key))
                values.append(value)
            else:
                raise InvalidRequestError()
        result = self._session.query(User).filter(
                tuple_(*keys).in_([tuple(values)])
                ).first()
        if result is None:
            raise NoResultFound()
        return result

    def update_user(self, user_id: int, **kwargs) -> None:
        """update the user’s attributes as passed in
            the method’s arguments
        """
        user_to_update = self.find_user_by(id=user_id)

        if user_to_update is None:
            return
        to_update = {}

        for key, value in kwargs.items():
            if hasattr(User, key):
                to_update[getattr(User, key)] = value
            else:
                raise ValueError()

        self._session.query(User).filter(User.id == user_id).update(
                to_update,
                synchronize_session=False,
                )
        self._session.commit()
