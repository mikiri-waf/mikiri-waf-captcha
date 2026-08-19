#!/usr/bin/env python3

"""
Mikiri WAF CAPTCHA
Copyright (c) Mikiri Security, LLC
Author: Romanov R.
"""

from multiprocessing import cpu_count
from logger import log

# Socket path
bind = "127.0.0.1:8080"

# Worker options
workers = cpu_count() + 1

# Logging options
loglevel = 'critical'
logconfig = '/var/www/mikiri-waf-captcha/logging.conf'

# Logging
log.info('START')
