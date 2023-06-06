#!/usr/bin/env python3
""" Password encryption module.
"""
from db import DB
from user import User
from sqlalchemy.orm.exc import NoResultFound
from typing import Union
import bcrypt
import uuid


def _hash_password(password: str) -> bytes:
    """ Takes a string, password, and returns a salted hash thereof.

    Args:
        - password (str): password to hash.
    Returns:
        - bytes: salted hash.
    """
    # TODO: password type validation
    return bcrypt.hashpw(password.encode(), bcrypt.gensalt())


class Auth:
    """Auth class to interact with the authentication database.
    """

    def __init__(self):
        self._db = DB()

    def register_user(self, email: str, password: str) -> User:
        """ Returns a User registered based on the arguments.

        Args:
            - email (str): user's email.
            - password (str): user's password.
        Returns:
            - User: a User instance object.
        """
        # TODO: email and password type validation
        if email is None or\
                not isinstance(email, str) or\
                password is None or\
                not isinstance(password, str):
            raise ValueError

        # ensure the email is unique in the database
        db = self._db
        new_user = None
        try:
            user = db.find_user_by(email=email)
            if user:
                # email already exists
                raise ValueError("User {} already exists".format(email))
        except NoResultFound:
            # email can be safely used to create new record
            hashed_pwd = _hash_password(password)
            new_user = db.add_user(email, hashed_pwd.decode())
        return new_user

    def valid_login(self, email: str, password: str) -> bool:
        """ Checks if supplied credentials are valid.
        """
        if email is None or\
                password is None or\
                not isinstance(email, str) or\
                not isinstance(password, str):
            return False

        db = self._db

        try:
            user = db.find_user_by(email=email)
            hashed_pwd = user.hashed_password.encode()
            return bcrypt.checkpw(password.encode(), hashed_pwd)
        except NoResultFound:
            # invalid credentials
            return False

        return False

    def _generate_uuid(self) -> str:
        """ Return a string representation of a new UUID.
        """
        return str(uuid.uuid4())

    def create_session(self, email: str) -> Union[str, None]:
        """ Takes an email string argument and returns the string session ID.
        """
        db = self._db

        try:
            # find user having email; ValueError will be raised if none found
            user = db.find_user_by(email=email)
        except NoResultFound:
            return None
        # generate session ID for user
        sess_id = self._generate_uuid()
        # persist this data
        db.update_user(user.id, session_id=sess_id)

        return sess_id

    def get_user_from_session_id(self, session_id: str) -> Union[User, None]:
        """ Returns the User object associated with session_id, or None.
        """
        db = self._db

        if session_id is None or type(session_id) is not str:
            return None

        try:
            user = db.find_user_by(session_id=session_id)
            return user
        except NoResultFound:
            return None

    def destroy_session(self, user_id: int) -> None:
        """ Updates the corresponding user's session ID to None.
        """
        db = self._db

        if user_id is None or type(user_id) is not int:
            return  # returns None

        try:
            db.update_user(user_id, session_id=None)
        except ValueError:
            # no associated user found
            return None

    def get_reset_password_token(self, email: str) -> str:
        """ Takes an email string argument and returns a reset token string.
        """
        if email is None or type(email) is not str:
            raise ValueError

        # fetch corresponding User
        db = self._db
        try:
            user = db.find_user_by(email=email)
            # user exists; generate, save and return reset token
            reset_token = self._generate_uuid()
            db.update_user(user.id, reset_token=reset_token)
            return reset_token
        except NoResultFound:
            # no User found
            raise ValueError

    def update_password(self, reset_token: str, password: str) -> None:
        """ Updates the password of a User having a reset token.
        """
        if reset_token is None or\
                password is None or\
                type(reset_token) is not str or\
                type(password) is not str:
            raise ValueError

        # fetch corresponding user
        db = self._db
        try:
            user = db.find_user_by(reset_token=reset_token)
            # User found; update password and reset_token attributes
            hashed_pwd = _hash_password(password)
            db.update_user(
                    user.id,
                    hashed_password=hashed_pwd.decode(),
                    reset_token=None,
                    )
        except NoResultFound:
            # no User with reset_token found
            raise ValueError


'''
class DB:
    """DB class
    """

    def __init__(self) -> None:
        """Initialize a new DB instance
        """
        self._engine = create_engine("sqlite:///a.db", echo=False)
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
        """ Creates and returns a new User.
        """
        # create a user object
        user = User(email=email, hashed_password=hashed_password)
        # retrieve a database session
        sess = self._session
        # save User to database
        sess.add(user)
        sess.commit()

        return user

    def find_user_by(self, **kwargs: dict) -> User:
        """ Filters User objects based on kwargs, and returns the first.
        """
        sess = self._session

        # InvalidRequestError will be raised for non-existent attributes
        user = sess.query(User).filter_by(**kwargs).first()
        if user is None:
            raise NoResultFound

        return user

    def update_user(self, user_id: int, **kwargs: dict) -> None:
        """ Updates a User record.
        """
        sess = self._session

        try:
            user = self.find_user_by(id=user_id)
        except NoResultFound:
            raise ValueError

        # User object exists based on ID
        for k, v in kwargs.items():
            if not hasattr(user, k):
                # attribute non-existent
                raise ValueError

            # else attribute exists; update
            setattr(user, k, v)
            sess.add(user)
            sess.commit()
'''
