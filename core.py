#!/usr/bin/env python3

"""
Mikiri WAF CAPTCHA
Copyright (c) Mikiri Security, LLC
Author: Romanov R.
"""

import io
import json
import numpy as np
import random

from math import sin
from PIL import Image, ImageDraw, ImageFont
from pymemcache.client.base import Client

from logger import log

##

memc_prefix = 'mikiri-waf-captcha_'
hdr_cpass_complete = {'x-waf-captcha-challenge': 'complete'}
hdr_cpass_progress = {'x-waf-captcha-challenge': 'progress'}

##

mclient = Client(('127.0.0.1', 11211), connect_timeout=1, no_delay=True)


def captcha_qa_gen():

    num1 = random.randint(1, 10)
    num2 = random.randint(1, 50)
    # operator = random.choice(['+', '-'])
    operator = '+'

    answer = num1 + num2 if operator == '+' else num1 - num2
    question = '{} {} {}'.format(num1, operator, num2)

    return question, str(answer)


def apply_wave_distortion(image, amplitude, wavelength):

    img_array = np.array(image)
    height, width = img_array.shape[:2]
    new_img = Image.new('RGB', (width, height), color='white')
    new_array = np.array(new_img)

    for y in range(height):
        for x in range(width):
            new_x = x + int(amplitude * sin(2 * 3.14 * y / wavelength))
            if 0 <= new_x < width:
                new_array[y, new_x] = img_array[y, x]

    return Image.fromarray(new_array)


def captcha_img_gen(sid):
    try:

        # receive data from the memcached
        memout = mclient.get(memc_prefix + sid)
        if not memout:
            return None

        # drawing the text
        image = Image.new('RGB', (200, 80), color='white')
        draw = ImageDraw.Draw(image)
        font = ImageFont.load_default(20)
        text = json.loads(memout).get('question')
        draw.text((40, 40), text, fill='black', font=font)

        # wave distortion
        image = apply_wave_distortion(image, 40, 80)

        # noise
        draw = ImageDraw.Draw(image)
        for _ in range(100):
            x = random.randint(0, 199)
            y = random.randint(0, 79)
            draw.point((x, y), fill=(random.randint(0, 255), random.randint(0, 255), random.randint(0, 255)))

        # convert the image
        img_byte_arr = io.BytesIO()
        image.save(img_byte_arr, format='PNG')
        img_byte_arr.seek(0)

        # return the image
        return img_byte_arr

    except Exception as e:
        log.error('An error occurred during CAPTCHA generation for SID {}: {}'.format(sid, e))
        return None


def request_preprocessing(request):
    try:

        # init
        sid = str(id(request))

        # captcha generation
        question, answer = captcha_qa_gen()

        # update the sessions
        mclient.set(
            memc_prefix + sid,
            json.dumps({
                'answer': answer,
                'question': question,
            }), 60
        )

        # return
        return sid

    except Exception as e:
        log.error('An error occurred while processing IP unblocking request: {}'.format(e))

    # default response
    return None
