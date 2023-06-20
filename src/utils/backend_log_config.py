import logging


def logger_backend():
    backend_logger = logging.getLogger(__name__)
    backend_logger.setLevel(logging.DEBUG)

    formatter = logging.Formatter('%(asctime)s:%(filename)s:%(funcName)s:%(levelname)s:%(message)s:')

    backend_file_handler = logging.FileHandler('./logs/backend.log')
    backend_file_handler.setLevel(logging.DEBUG)
    backend_file_handler.setFormatter(formatter)

    backend_logger.addHandler(backend_file_handler)

    return backend_logger


backend = logger_backend()
