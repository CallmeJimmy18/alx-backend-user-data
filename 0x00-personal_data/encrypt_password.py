#!/usr/bin/env python3
"""hash_password"""
import bcrypt


def hash_password(password: str) -> bytes:
    """returns a salted, hashed password"""
    salted = bcrypt.gensalt()

    hashed_password = bcrypt.hashpw(password.encode('utf-8'), salted)
    return hashed_password


def is_valid(hashed_password: bytes, password: str) -> bool:
    """validate that the provided password matches the hashed password"""
    return bcrypt.checkpw(password.encode('utf-8'), hashed_password)
