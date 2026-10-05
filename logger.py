#!/usr/bin/env python3

"""
Mikiri WAF API
Copyright (c) Mikiri Security, LLC
Author: Romanov R.
"""

import logging

##
# Log settings
##

logf = '/var/log/mikiri-waf/captcha/api.log'
log = logging.getLogger(__name__)
log.setLevel(logging.INFO)
# Gunicorn sends root ERROR records to error.log. Propagating would store
# every application error in both files.
log.propagate = False

# The master imports this module, then forks. A worker imports it again and
# must not attach a second handler to the inherited logger.
if not log.handlers:
    formatter = logging.Formatter('%(asctime)s %(levelname)-8s %(message)s')
    file_handler = logging.FileHandler(logf)
    file_handler.setFormatter(formatter)
    log.addHandler(file_handler)
