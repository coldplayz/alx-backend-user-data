#!/usr/bin/env python3
"""
Main file
"""

import logging

get_logger = __import__('filtered_logger').get_logger
PII_FIELDS = __import__('filtered_logger').PII_FIELDS

print(get_logger.__annotations__.get('return'))
print("PII_FIELDS: {}".format(len(PII_FIELDS)))

fo = open('/home/userland/alx-backend-user-data/0x00-personal_data/user_data.csv')

logger = get_logger()

fields = []
n = 0
for line in fo:
    if n == 0:
        fields = line.split(',')
    else:
        values = line.split(',')
        msg_list = [fields[i] + '=' + values[i] for i in range(len(fields))]
        str_msg = (";".join(msg_list)).replace('"', '')
        logger.info(str_msg)
        # print(str_msg)
    n += 1

fo.close()
