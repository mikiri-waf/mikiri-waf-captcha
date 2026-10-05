#!/usr/bin/env python3

"""
Mikiri WAF CAPTCHA
Copyright (c) Mikiri Security, LLC
Author: Romanov R.
"""

from fastapi import FastAPI, Request, Form
from fastapi.responses import Response, HTMLResponse, StreamingResponse
from fastapi.templating import Jinja2Templates

from core import answers_match
from core import captcha_img_gen
from core import hdr_cpass_progress
from core import hdr_cpass_complete
from core import request_preprocessing
from core import session_drop
from core import session_get

from logger import log

##

app = FastAPI(redirect_slashes=False, docs_url=None, redoc_url=None, openapi_url=None)
templates = Jinja2Templates(directory='templates')

##

# headers of the CAPTCHA page: the service header plus the CORS fix
hdr_page = {
    **{
        'Access-Control-Allow-Origin': '*',
        'Access-Control-Allow-Headers': 'x-waf-antibot-id, x-waf-antibot-validation'
    },
    **hdr_cpass_progress
}


def error_response(status_code=500):
    """
    Answer of a broken CAPTCHA.

    It carries no x-waf-captcha-challenge header on purpose: the filter has to
    treat such an answer as a failed exchange, write it to its log and give the
    status code back to the client instead of showing an unusable page.
    """

    return Response(status_code=status_code)


def expired_response(status_code=400):
    """
    Answer to a request of an expired or unknown session.

    The CAPTCHA itself works, the challenge is simply not passed yet, so the
    service header is present and the filter relays the answer as it is.
    """

    return Response(status_code=status_code, headers=hdr_cpass_progress)


async def captcha_page(request, status=0):
    """Renders the CAPTCHA page with a freshly created session."""

    sid = await request_preprocessing()
    if not sid:
        return error_response()

    return templates.TemplateResponse(
        request=request,
        name='index.html',
        headers=hdr_page,
        context={'sid': sid, 'status': status}
    )


@app.get('/', response_class=HTMLResponse)
@app.post('/', response_class=HTMLResponse)
@app.options('/', response_class=HTMLResponse)
async def main(request: Request):
    try:
        return await captcha_page(request)

    except Exception as e:
        log.error('An error occurred in /: {}'.format(e))
        return error_response()


@app.get('/captcha')
async def captcha(request: Request):
    try:
        sid = request.query_params.get('sid')
        r = await captcha_img_gen(sid)

        if not r:
            return expired_response()

        return StreamingResponse(r, media_type='image/png', headers=hdr_cpass_progress,
                                 status_code=200)

    except Exception as e:
        log.error('An error occurred in /captcha: {}'.format(e))
        return error_response()


# the form fields are optional on purpose: a submit without them has to get
# a new challenge and not a validation error without the service header
@app.post('/verify', response_class=HTMLResponse)
async def verify(request: Request, sid: str = Form(default=''), answer: str = Form(default='')):
    try:

        # receive data from the memcached
        expected = await session_get(sid)

        # the session is unknown or has expired: a new challenge
        if expected is None:
            return await captcha_page(request, status=0)

        # success validation
        if answers_match(answer, expected):
            # a solved challenge must not be reusable
            await session_drop(sid)
            return Response(content=None, headers=hdr_cpass_complete, status_code=200)

        # fail validation
        return await captcha_page(request, status=1)

    except Exception as e:
        log.error('An error occurred in /verify: {}'.format(e))
        return error_response()


@app.api_route('/{path:path}', response_class=HTMLResponse,
               methods=['GET', 'HEAD', 'POST', 'PUT', 'PATCH', 'DELETE', 'OPTIONS'])
async def any_path(request: Request):
    """
    The filter proxies the request of the blocked client as it is, so the
    CAPTCHA is asked for the path the client was heading to. Every path that
    is not one of the CAPTCHA endpoints above answers with the CAPTCHA page,
    otherwise the filter would receive a 404 without the service header.
    """
    try:
        return await captcha_page(request)

    except Exception as e:
        log.error('An error occurred in /{}: {}'.format(request.path_params.get('path', ''), e))
        return error_response()
