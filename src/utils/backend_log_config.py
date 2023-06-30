"""
Configuration module for model server logs
"""

import logging
from logging import Logger


def logger_backend() -> Logger:
    """Format logger, configure file handler and add handler
    for backend logger.

    Returns:
        Logger: Logger for model server side
    """    
    
    backend_logger = logging.getLogger(__name__)
    backend_logger.setLevel(logging.DEBUG)

    formatter = logging.Formatter('%(asctime)s:%(filename)s:%(funcName)s:%(levelname)s:%(message)s:')

    backend_file_handler = logging.FileHandler('./logs/backend.log')
    backend_file_handler.setLevel(logging.DEBUG)
    backend_file_handler.setFormatter(formatter)

    backend_logger.addHandler(backend_file_handler)

    return backend_logger


backend = logger_backend()
