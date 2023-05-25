#!/usr/bin/env python3
"""Redact logs with regex.
"""
from typing import List, Sequence
import logging
import re
import mysql.connector
import os

pr = r'(.*{}?{}=).*?(;.*)'  # field regex
r = r'\1{}\2'  # replacement


def filter_datum(
        fields: List[str],
        redaction: str,
        message: str,
        separator: str
        ) -> str:
    """Returns the log `message` obfuscated."""
    rdt = message
    for field in fields:
        rdt = re.sub(pr.format(separator, field), r.format(redaction), rdt)
    return rdt


def get_logger() -> logging.Logger:
    """Returns the `user_data` logger.
    """
    # create logger, or retrieve if previously created
    logger = logging.getLogger('user_data')  # returns same logger next time

    # set log level
    logger.setLevel(logging.INFO)

    # prevent propagation of messages to parent loggers
    logger.propagate = False

    # create handler for logger
    handler = logging.StreamHandler()  # logs to console
    # create formatter for handler
    formatter = RedactingFormatter(PII_FIELDS)
    handler.setFormatter(formatter)

    # attach handler to logger
    logger.addHandler(handler)

    return logger


# retrieve database credentials
user = os.getenv('PERSONAL_DATA_DB_USERNAME')
pwd = os.getenv('PERSONAL_DATA_DB_PASSWORD')
host = os.getenv('PERSONAL_DATA_DB_HOST')
db = os.getenv('PERSONAL_DATA_DB_NAME')


def get_db() -> mysql.connector.connection.MySQLConnection:
    """Returns a connector to a database.
    """
    connector = mysql.connector.connection.MySQLConnection(
            host=host,
            user=user,
            password=pwd,
            database=db,
            )
    return connector


class RedactingFormatter(logging.Formatter):
    """ Redacting Formatter class
    """

    REDACTION = "***"
    FORMAT = "[HOLBERTON] %(name)s %(levelname)s %(asctime)-15s: %(message)s"
    SEPARATOR = ";"

    def __init__(self, fields: List[str]):
        super(RedactingFormatter, self).__init__(self.FORMAT)
        self.fields = fields

    def format(self, record: logging.LogRecord) -> str:
        """ Filters message, formats and returns the formated string."""
        msg = record.msg
        f_msg = filter_datum(self.fields, self.REDACTION, msg, self.SEPARATOR)
        record.msg = f_msg
        return super().format(record)


PII_FIELDS = ('name', 'email', 'phone', 'ssn', 'password')
