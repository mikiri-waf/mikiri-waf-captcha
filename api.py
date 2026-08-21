#!/usr/bin/env python3

"""
Mikiri WAF CAPTCHA
Copyright (c) Mikiri Security, LLC
Author: Romanov R.
"""

import json

from fastapi import FastAPI, Request, Form
from fastapi.responses import Response, HTMLResponse, StreamingResponse
from fastapi.templating import Jinja2Templates

from core import captcha_img_gen
from core import hdr_cpass_progress
from core import hdr_cpass_complete
from core import mclient
from core import memc_prefix
from core import request_preprocessing

from logger import log

##

app = FastAPI(redirect_slashes=False, ocs_url=None, redoc_url=None, openapi_url=None)
templates = Jinja2Templates(directory='templates')

##

@app.get('/', response_class=HTMLResponse)
@app.post('/', response_class=HTMLResponse)
@app.options('/', response_class=HTMLResponse)
async def main(request: Request):
    try:

        # request preprocessing
        r = request_preprocessing(request)

        # CORS issue fix
        hdrs = {
            **{
                'Access-Control-Allow-Origin': '*',
                'Access-Control-Allow-Headers': 'x-waf-antibot-id, x-waf-antibot-validation'
            },
            **hdr_cpass_progress
        }

        # response
        if r:

            # OK: request with query
            if r:
                return templates.TemplateResponse(
                    request=request,
                    headers=hdrs,
                    name='index.html',
                    context={"sid": r}
                )

            # FAIL: no query in request
            else:
                return Response('Incorrect or empty query', status_code=403)

        else:
            return Response(status_code=400)

    except Exception as e:
        log.error('An error occurred in /: {}'.format(e))


@app.get('/captcha')
async def main(request: Request):
    try:
        sid = str(request.query_params.get('sid'))
        r = captcha_img_gen(sid)
        return Response(status_code=400) if r is None else StreamingResponse(r, media_type='image/png', status_code=200)
    except Exception as e:
        log.error('An error occurred in /captcha: {}'.format(e))


@app.post('/verify', response_class=HTMLResponse)
async def main(request: Request, sid: str = Form(...), answer: str = Form(...)):
    try:

        # receive data from the memcached
        memout = mclient.get(memc_prefix + sid)
        if not memout:

            # request preprocessing
            r = request_preprocessing(request)

            # response
            if r:
                return templates.TemplateResponse(
                    name='index.html',
                    headers=hdr_cpass_progress,
                    request={'request': request, 'sid': r, 'status': 0}
                )
            else:
                return Response(status_code=400)

        # success validation
        if str(answer) == str(json.loads(memout).get('answer')):
            return Response(content=None, headers=hdr_cpass_complete, status_code=200)

        # fail validation
        else:

            # request preprocessing
            r = request_preprocessing(request)

            # response
            if r:
                return templates.TemplateResponse(
                    name='index.html',
                    headers=hdr_cpass_progress,
                    request={'request': request, 'sid': r, 'status': 1}
                )
            else:
                return Response(status_code=400)

    except Exception as e:
        log.error('An error occurred in /verify: {}'.format(e))
