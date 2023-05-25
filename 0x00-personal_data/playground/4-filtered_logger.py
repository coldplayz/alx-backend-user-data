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


def main() -> None:
    """Retrieve rows from the database and log using the custom formatter.
    """
    # get `my_db` database connector
    # TODO: close connection
    connector = get_db()

    # get a cursor
    # TODO: close cursor
    cursor = connector.cursor()

    # retrieve all rows from users table
    cursor.execute('SELECT * FROM users')  # result stored in cursor; iterable
    rows_list = cursor.fetchall()  # list of rows of the result set
    fields_tuple = cursor.column_names

    # get logger
    logger = get_logger()

    # logging time
    for row in rows_list:
        msg_list = []
        # take each row...
        for field, value in zip(fields_tuple, row):
            # ...and map to its field to create a log message field/unit
            msg_field = "{}={}".format(field, value)
            msg_list.append(msg_field)
        # join all message fields into the actual message
        msg = ";".join(msg_list)
        # log message
        logger.info(msg)

    cursor.close()  # DONE: close cursor
    connector.close()  # DONE: close connection


PII_FIELDS = ('name', 'email', 'phone', 'ssn', 'password')

if __name__ == '__main__':
    main()
