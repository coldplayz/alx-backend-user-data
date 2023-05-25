#!/usr/bin/env python3
"""Encrypt passwords with bcrypt.
"""
import bcrypt


def hash_password(password: str) -> bytes:
    """Returns a salted, hashed password from @password.

    Args:
        password (str): the password to hash.

    Returns:
        bytes: a bytes string representing the hash.
    """
    return bcrypt.hashpw(password.encode(), bcrypt.gensalt())


def is_valid(hashed_password: bytes, password: str) -> bool:
    """Checks if @hashed_password is the hash of @password.
    """
    return bcrypt.checkpw(password.encode(), hashed_password)
