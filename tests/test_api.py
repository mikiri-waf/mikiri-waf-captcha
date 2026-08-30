#!/usr/bin/env python3

"""
Mikiri WAF CAPTCHA - tests
Copyright (c) Mikiri Security, LLC

Drives the CAPTCHA ASGI application directly, with an in-memory stand-in for
the memcached, and checks the contract the Mikiri WAF filter relies on: every
answer of a working CAPTCHA carries the x-waf-captcha-challenge header, any
proxied path is answered with the CAPTCHA page, and a broken CAPTCHA answers
without the service header so that the filter reports it.

No memcached and no extra packages are needed, only the ones from
requirements.txt.

    python3 tests/test_api.py
"""

import asyncio
import json
import logging
import os
import re
import sys
import types

from urllib.parse import urlencode

REPO = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))

# the application logger writes to /var/log, replace it before the app is imported
_logger = types.ModuleType('logger')
_logger.log = logging.getLogger('captcha-test')
_logger.log.addHandler(logging.NullHandler())
sys.modules['logger'] = _logger

# the templates directory is resolved relative to the working directory
os.chdir(REPO)
sys.path.insert(0, REPO)

import core                                                       # noqa: E402


class FakeMemcache(object):
    """Enough of pymemcache for the CAPTCHA."""

    def __init__(self):
        self.store = {}
        self.broken = False

    def get(self, key):
        if self.broken:
            raise RuntimeError('memcached is down')
        return self.store.get(key)

    def set(self, key, value, ttl):
        if self.broken:
            raise RuntimeError('memcached is down')
        self.store[key] = value.encode() if isinstance(value, str) else value

    def delete(self, key):
        if self.broken:
            raise RuntimeError('memcached is down')
        self.store.pop(key, None)


mc = FakeMemcache()
core.mclient = mc

import api                                                        # noqa: E402

##

CHALLENGE = 'x-waf-captcha-challenge'
SID_RE = re.compile(r'name="sid"\s+value="([^"]+)"')

failures = []


def check(cond, name):
    if cond:
        print('ok   {}'.format(name))
    else:
        failures.append(name)
        print('FAIL {}'.format(name))


async def _call(method, path, query=b'', body=b'', content_type=None):

    headers = [(b'host', b'shop.example.com')]
    if content_type:
        headers.append((b'content-type', content_type))
        headers.append((b'content-length', str(len(body)).encode()))

    scope = {
        'type': 'http',
        'asgi': {'version': '3.0', 'spec_version': '2.3'},
        'http_version': '1.1',
        'method': method,
        'scheme': 'http',
        'path': path,
        'raw_path': path.encode(),
        'query_string': query,
        'root_path': '',
        'headers': headers,
        'client': ('203.0.113.7', 40000),
        'server': ('127.0.0.1', 8080),
        'app': api.app,
    }

    received = {'done': False}
    never = asyncio.Event()

    async def receive():
        # after the body a live client stays connected; returning a disconnect
        # right away would cancel a StreamingResponse before it is written out
        if received['done']:
            await never.wait()
        received['done'] = True
        return {'type': 'http.request', 'body': body, 'more_body': False}

    out = {'status': None, 'headers': [], 'body': b''}

    async def send(message):
        if message['type'] == 'http.response.start':
            out['status'] = message['status']
            out['headers'] = message.get('headers', [])
        elif message['type'] == 'http.response.body':
            out['body'] += message.get('body', b'')

    await api.app(scope, receive, send)

    hdrs = {}
    for k, v in out['headers']:
        hdrs.setdefault(k.decode().lower(), v.decode())

    return out['status'], hdrs, out['body']


def call(method, path, query=b'', body=b'', content_type=None):
    return asyncio.run(_call(method, path, query, body, content_type))


def form(**kw):
    return urlencode(kw).encode()


def page_sid(body):
    """The session id rendered into the CAPTCHA page."""

    m = SID_RE.search(body.decode())
    return m.group(1) if m else None


def answer_for(sid):
    """Reads the expected answer straight from the session storage."""

    raw = mc.store.get(core.memc_prefix + sid)
    return json.loads(raw).get('answer') if raw else None


##

def test_page():

    st, h, b = call('GET', '/')
    check(st == 200, 'GET / status 200')
    check(h.get(CHALLENGE) == 'progress', 'GET / progress header')
    check(h.get('access-control-allow-origin') == '*', 'GET / CORS header kept')

    sid = page_sid(b)
    check(sid is not None and core.valid_sid(sid), 'GET / page carries a valid sid')
    check(b'Verification failed' not in b, 'GET / no failure notice on a fresh page')

    # the session id must not be an object address any more
    check(not sid.isdigit(), 'sid is not a memory address')
    check(page_sid(call('GET', '/')[2]) != sid, 'every page gets its own sid')


def test_any_path():
    """The filter proxies the request as it is, whatever the path and method."""

    for method, path in (('GET', '/shop/item'), ('POST', '/shop/item'),
                         ('PUT', '/api/v1/order'), ('DELETE', '/api/v1/order'),
                         ('GET', '/docs'), ('GET', '/a/b/c/d')):
        st, h, b = call(method, path, query=b'id=5')
        check(st == 200, '{} {} status 200'.format(method, path))
        check(h.get(CHALLENGE) == 'progress', '{} {} progress header'.format(method, path))
        check(page_sid(b) is not None, '{} {} serves the captcha page'.format(method, path))

    st, h, b = call('OPTIONS', '/')
    check(st == 200 and h.get(CHALLENGE) == 'progress', 'OPTIONS / answered')


def test_picture():

    sid = page_sid(call('GET', '/')[2])

    st, h, b = call('GET', '/captcha', query='sid={}'.format(sid).encode())
    check(st == 200, 'GET /captcha status 200')
    check(h.get(CHALLENGE) == 'progress', 'GET /captcha progress header')
    check(h.get('content-type') == 'image/png', 'GET /captcha content type')
    check(b[:4] == b'\x89PNG', 'GET /captcha returns a PNG')

    st, h, b = call('GET', '/captcha', query=b'sid=nosuchsession0000000')
    check(st == 400, 'GET /captcha unknown sid -> 400')
    check(h.get(CHALLENGE) == 'progress',
          'GET /captcha unknown sid keeps the service header, the filter relays it')

    st, h, b = call('GET', '/captcha')
    check(st == 400, 'GET /captcha without sid -> 400')

    st, h, b = call('GET', '/captcha', query=b'sid=../../../etc/passwd')
    check(st == 400, 'GET /captcha rejects a malformed sid')


def test_verify_success():

    sid = page_sid(call('GET', '/')[2])
    good = answer_for(sid)

    st, h, b = call('POST', '/verify', body=form(sid=sid, answer=good),
                    content_type=b'application/x-www-form-urlencoded')
    check(st == 200, 'correct answer -> 200')
    check(h.get(CHALLENGE) == 'complete', 'correct answer -> complete')
    check(b == b'', 'correct answer -> empty body')

    # a solved session must not be usable a second time
    st, h, b = call('POST', '/verify', body=form(sid=sid, answer=good),
                    content_type=b'application/x-www-form-urlencoded')
    check(h.get(CHALLENGE) == 'progress', 'a solved session cannot be replayed')


def test_verify_failure():
    """After a wrong answer the page has to stay usable."""

    sid = page_sid(call('GET', '/')[2])
    wrong = str(int(answer_for(sid)) + 1)

    st, h, b = call('POST', '/verify', body=form(sid=sid, answer=wrong),
                    content_type=b'application/x-www-form-urlencoded')
    check(st == 200, 'wrong answer -> 200')
    check(h.get(CHALLENGE) == 'progress', 'wrong answer -> progress')

    new_sid = page_sid(b)
    check(new_sid is not None and core.valid_sid(new_sid),
          'wrong answer -> the page carries a new sid')
    check(new_sid != sid, 'wrong answer -> the sid is regenerated')
    check(b'Verification failed' in b, 'wrong answer -> the failure notice is rendered')
    check('src="/captcha?sid={}"'.format(new_sid).encode() in b,
          'wrong answer -> the picture url carries the sid')

    st, h, b = call('POST', '/verify', body=form(sid=new_sid, answer=answer_for(new_sid)),
                    content_type=b'application/x-www-form-urlencoded')
    check(h.get(CHALLENGE) == 'complete', 'the session from the failure page is usable')


def test_verify_malformed():
    """No submit may be answered without the service header."""

    st, h, b = call('POST', '/verify', body=form(sid='unknownsession000000', answer='1'),
                    content_type=b'application/x-www-form-urlencoded')
    check(st == 200 and h.get(CHALLENGE) == 'progress', 'unknown session -> new challenge')
    check(page_sid(b) is not None, 'unknown session -> page with a sid')

    st, h, b = call('POST', '/verify', body=b'',
                    content_type=b'application/x-www-form-urlencoded')
    check(st == 200 and h.get(CHALLENGE) == 'progress', 'empty submit -> new challenge')
    check(page_sid(b) is not None, 'empty submit -> page with a sid')

    st, h, b = call('POST', '/verify', body=b'{"sid": 1}', content_type=b'application/json')
    check(h.get(CHALLENGE) == 'progress', 'non-form submit -> service header present')

    st, h, b = call('POST', '/verify')
    check(h.get(CHALLENGE) == 'progress', 'submit without a body -> service header present')


def test_broken_captcha():
    """
    When the CAPTCHA cannot work the answer carries no service header, so the
    filter writes the failure to its log and gives the code back to the client.
    """

    mc.broken = True
    try:
        st, h, b = call('GET', '/')
        check(st == 500, 'memcached down -> 500')
        check(CHALLENGE not in h, 'memcached down -> no service header')

        st, h, b = call('GET', '/shop/item')
        check(st == 500 and CHALLENGE not in h,
              'memcached down on any path -> 500 without header')

        st, h, b = call('POST', '/verify', body=form(sid='someothersession0000', answer='1'),
                        content_type=b'application/x-www-form-urlencoded')
        check(st == 500 and CHALLENGE not in h,
              'memcached down on /verify -> 500 without header')
    finally:
        mc.broken = False


def main():

    for test in (test_page, test_any_path, test_picture, test_verify_success,
                 test_verify_failure, test_verify_malformed, test_broken_captcha):
        test()

    print('')
    print('{} ({} failures)'.format('FAILED' if failures else 'PASSED', len(failures)))

    return 1 if failures else 0


if __name__ == '__main__':
    sys.exit(main())
