import logging


def logger_pipeline():
    pipeline_logger = logging.getLogger(__name__)
    pipeline_logger.setLevel(logging.DEBUG)

    formatter = logging.Formatter('%(asctime)s:%(filename)s:%(funcName)s:%(levelname)s:%(message)s:')

    pipeline_file_handler = logging.FileHandler('./logs/pipeline.log')
    pipeline_file_handler.setLevel(logging.DEBUG)
    pipeline_file_handler.setFormatter(formatter)

    pipeline_logger.addHandler(pipeline_file_handler)

    return pipeline_logger


pipeline = logger_pipeline()