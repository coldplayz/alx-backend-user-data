#!/usr/bin/env python3
"""Redact logs with regex.
"""
import re
from typing import List

pr = r'(.*{}password=).*?(;.*)'  # password regex
dr = r'(.*{}date_of_birth=).*?(;.*)'  # dob regex
r = r'\1{}\2'  # replacement


def filter_datum(
        fields: List[str],
        redaction: str,
        message: str,
        separator: str
        ) -> str:
    """Returns the log `message` obfuscated.
    """
    pwd_redact = re.sub(pr.format(separator), r.format(redaction), message)
    dob_redact = re.sub(dr.format(separator), r.format(redaction), pwd_redact)
    return dob_redact
