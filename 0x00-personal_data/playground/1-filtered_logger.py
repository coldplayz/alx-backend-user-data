#!/usr/bin/env python3
"""Redact logs with regex.
"""
import logging
import re
from typing import List

pr = r'(.*{}{}=).*?(;.*)'  # field regex
r = r'\1{}\2'  # replacement


def filter_datum(
        fields: List[str],
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
