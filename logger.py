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
formatter = logging.Formatter('%(asctime)s %(levelname)-8s %(message)s')
file_handler = logging.FileHandler(logf)
file_handler.setFormatter(formatter)
log.addHandler(file_handler)
