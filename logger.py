# -*- coding: utf-8 -*-
# pylint: disable= C0103,C0114,C0116

import logging

_logger = logging.getLogger('teleparser')

critical = _logger.critical
debug = _logger.debug
error = _logger.error
exception = _logger.exception
info = _logger.info
log = _logger.log
warning = _logger.warning

def configure_logging(verbosity=None):
    for handler in logging.root.handlers:
        logging.root.removeHandler(handler)

    logger = logging.getLogger()

    handler = logging.StreamHandler()

    format_string = (
        '%(asctime)s [%(levelname)s] (%(module)s) %(message)s')

    formatter = logging.Formatter(format_string)
    handler.setFormatter(formatter)

    log_level = logging.DEBUG
    if not verbosity:
        log_level = logging.ERROR
    elif verbosity == 1:
        log_level = logging.WARNING
    elif verbosity == 2:
        log_level = logging.INFO
    elif verbosity >= 3:
        log_level = logging.DEBUG

    logger.setLevel(log_level)
    handler.setLevel(log_level)

    logger.addHandler(handler)
