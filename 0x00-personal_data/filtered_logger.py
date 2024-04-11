#!/usr/bin/env python3
"""filter_datum"""
import logging
from typing import List
import re
from mysql.connector import connection
from os import environ


PII_FIELDS = ('name', 'email', 'password', 'ssn', 'phone')


def filter_datum(
        fields: List[str],
        redaction: str,
        message: str,
        separator: str
        ) -> str:
    """returns the log message obfuscated"""
    tmp_mess = message
    for field in fields:
        tmp_mess = re.sub(field + "=.*?" + separator,
                          field + "=" + redaction + separator, tmp_mess)

    return tmp_mess


def get_logger() -> logging.Logger:
    """returns a logging.Logger object"""
    logger = logging.getLogger("user_data")
    logger.setLevel(logging.INFO)
    logger.propagate = False

    strm_handler = logging.StreamHandler()
    formatter = RedactingFormatter(PII_FIELDS)
    strm_handler.setFormatter(formatter)
    logger.addHandler(strm_handler)

    return logger


def get_db() -> connection.MySQLConnection:
    """returns a connector to the database """
    username = environ.get("PERSONAL_DATA_DB_USERNAME", "root")
    password = environ.get("PERSONAL_DATA_DB_PASSWORD", "")
    db_host = environ.get("PERSONAL_DATA_DB_HOST", "localhost")
    db_name = environ.get("PERSONAL_DATA_DB_NAME")
    connector = connection.MySQLConnection(
            user=username,
            password=password,
            host=db_host,
            database=db_name)
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
        """ filter values in incoming log records using filter_datum"""
        filtered_vals = filter_datum(self.fields, self.REDACTION, super(
                                     RedactingFormatter, self).format(record),
                                     self.SEPARATOR)
        return filtered_vals


def main():
    """obtain a database connection using get_db and retrieve all rows"""
    con_db = get_db()
    cur = con_db.cursor()

    qry = ("SELECT * FROM users")
    cur.execute(qry)
    get_data = cur.fetchall()

    logger = get_logger()

    for row in get_data:
        fieldz = 'name={}; email={}; phone={}; ssn={}; password={}; ip={}; '\
            'last_login={}; user_agen={};'
        fieldz = fieldz.format(row[0], row[1], row[2], row[3], row[4],
                               row[5], row[6], row[7])
        logger.info(fieldz)

    cur.close()
    con_db.close()
