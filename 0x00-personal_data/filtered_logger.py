#!/usr/bin/env python3
"""Redact logs with regex.
"""
from typing import List, Sequence
import logging
import re

pr = r'(.*{}?{}=).*?(;.*)'  # field regex
r = r'\1{}\2'  # replacement


def filter_datum(
        fields: Sequence[str],
        redaction: str,
        message: str,
        separator: str
        ) -> str:
    """Returns the log `message` obfuscated."""
    redact = message
    for field in fields:
        redact = re.sub(
                pr.format(separator, field), r.format(redaction), redact)
    return redact


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


class RedactingFormatter(logging.Formatter):
    """ Redacting Formatter class
    """

    REDACTION = "***"
    FORMAT = "[HOLBERTON] %(name)s %(levelname)s %(asctime)-15s: %(message)s"
    SEPARATOR = ";"

    def __init__(self, fields: Sequence[str]):
        super(RedactingFormatter, self).__init__(self.FORMAT)
        self.fields = fields

    def format(self, record: logging.LogRecord) -> str:
        """ Filters message, formats and returns the formated string."""
        msg = record.msg
        f_msg = filter_datum(self.fields, self.REDACTION, msg, self.SEPARATOR)
        record.msg = f_msg
        return super().format(record)


PII_FIELDS = ('name', 'email', 'phone', 'ssn', 'password')
