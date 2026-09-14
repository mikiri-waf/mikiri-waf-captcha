#!/bin/bash

/var/www/mikiri-waf-captcha/venv/bin/python3 -m pip install --upgrade pip
/var/www/mikiri-waf-captcha/venv/bin/python3 -m pip install --upgrade wheel
/var/www/mikiri-waf-captcha/venv/bin/python3 -m pip freeze | sed -r 's|==.+||' > /tmp/requirements.txt
/var/www/mikiri-waf-captcha/venv/bin/python3 -m pip install --upgrade -r /tmp/requirements.txt
rm -f /tmp/requirements.txt
