"""
Configuration module for model client logs
"""

import logging
from logging import Logger


def logger_frontend() -> Logger:
    """Format logger, configure file handler and add handler
    for frontend logger.

    Returns:
        Logger: Logger for model client side
    """ 
    frontend_logger = logging.getLogger(__name__)
    frontend_logger.setLevel(logging.DEBUG)

    formatter = logging.Formatter('%(asctime)s:%(filename)s:%(funcName)s:%(levelname)s:%(message)s:')

    frontend_file_handler = logging.FileHandler('./logs/frontend.log')
    frontend_file_handler.setLevel(logging.DEBUG)
    frontend_file_handler.setFormatter(formatter)

    frontend_logger.addHandler(frontend_file_handler)

    return frontend_logger

frontend = logger_frontend()