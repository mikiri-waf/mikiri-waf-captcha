#!/usr/bin/env python3

"""
Mikiri WAF CAPTCHA - memcached pool tests

The pool has to hide a dead socket (the failure that dropped every other
captcha image), wait instead of failing when every connection is busy, and
confirm a set before it returns.

    python3 tests/test_memcache.py
"""

import os
import sys
import threading
import time

REPO = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
sys.path.insert(0, REPO)

from memcache import MemcachePool, MemcachePoolExhausted          # noqa: E402
from pymemcache.exceptions import MemcacheUnexpectedCloseError   # noqa: E402

failures = []


def check(cond, name):
    if cond:
        print('ok   {}'.format(name))
    else:
        failures.append(name)
        print('FAIL {}'.format(name))


class Scripted(object):
    def __init__(self, fail=None, value=b'ok'):
        self.fail = fail
        self.value = value
        self.closed = False
        self.set_noreply = None
        self.set_expire = None

    def get(self, key):
        if self.fail is not None:
            raise self.fail
        return self.value

    def set(self, key, value, expire=0, noreply=None):
        if self.fail is not None:
            raise self.fail
        self.set_noreply = noreply
        self.set_expire = expire
        return True

    def delete(self, key, noreply=None):
        if self.fail is not None:
            raise self.fail
        return True

    def close(self):
        self.closed = True


def factory_of(clients):
    pending = list(clients)

    def factory():
        return pending.pop(0)

    return factory


def test_retries_broken_pipe():
    dead = Scripted(fail=BrokenPipeError(32, 'Broken pipe'))
    live = Scripted(value=b'{"question": "1 + 1"}')
    pool = MemcachePool(
        ('127.0.0.1', 11211),
        max_size=4,
        checkout_timeout=0.5,
        idle_timeout=30,
        client_factory=factory_of([dead, live]),
    )

    check(pool.get('k') == b'{"question": "1 + 1"}', 'broken pipe is retried once')
    check(dead.closed, 'the dead socket is closed')
    check(not live.closed, 'the working socket stays in the pool')

    # the retried connection is reused, not opened again
    check(pool.get('k') == b'{"question": "1 + 1"}', 'the next get reuses the live socket')
    check(not live.closed, 'reuse does not close the live socket')


def test_retries_unexpected_close():
    # pymemcache raises this with an empty message when the peer closes
    # the socket while a reply is being read. That was the blank error line.
    dead = Scripted(fail=MemcacheUnexpectedCloseError())
    live = Scripted(value=b'ok')
    pool = MemcachePool(
        ('127.0.0.1', 11211),
        max_size=4,
        checkout_timeout=0.5,
        idle_timeout=30,
        client_factory=factory_of([dead, live]),
    )
    check(pool.get('k') == b'ok', 'unexpected close is retried once')
    check(dead.closed, 'the closed socket is not reused')


def test_does_not_retry_logic_errors():
    made = []

    def factory():
        client = Scripted(fail=RuntimeError('bad key'))
        made.append(client)
        return client

    pool = MemcachePool(
        ('127.0.0.1', 11211),
        max_size=4,
        checkout_timeout=0.5,
        idle_timeout=30,
        client_factory=factory,
    )
    try:
        pool.get('k')
        check(False, 'a logic error is raised')
    except RuntimeError:
        check(True, 'a logic error is raised')
    check(len(made) == 1, 'a logic error is not retried')
    check(made[0].closed, 'a failed socket is not returned to the pool')


def test_set_waits_for_reply():
    client = Scripted()
    pool = MemcachePool(
        ('127.0.0.1', 11211),
        max_size=2,
        checkout_timeout=0.5,
        idle_timeout=30,
        client_factory=factory_of([client]),
    )
    pool.set('k', 'v', 60)
    check(client.set_noreply is False, 'set waits for STORED')
    check(client.set_expire == 60, 'set keeps the session ttl')


def test_idle_socket_is_dropped():
    first = Scripted()
    second = Scripted(value=b'second')
    pool = MemcachePool(
        ('127.0.0.1', 11211),
        max_size=4,
        checkout_timeout=0.5,
        idle_timeout=0.05,
        client_factory=factory_of([first, second]),
    )
    check(pool.get('k') == b'ok', 'first get uses a fresh socket')
    time.sleep(0.08)
    check(pool.get('k') == b'second', 'an idle socket is replaced')
    check(first.closed, 'the idle socket is closed')


def test_pool_waits_instead_of_failing():
    hold = threading.Event()
    entered = threading.Event()
    current = {'n': 0, 'peak': 0}
    lock = threading.Lock()

    class Holding(object):
        def get(self, key):
            with lock:
                current['n'] += 1
                current['peak'] = max(current['peak'], current['n'])
                if current['n'] == 2:
                    entered.set()
            hold.wait(2)
            with lock:
                current['n'] -= 1
            return b'v'

        def close(self):
            pass

    pool = MemcachePool(
        ('127.0.0.1', 11211),
        max_size=2,
        checkout_timeout=1,
        idle_timeout=30,
        client_factory=Holding,
    )
    threads = [threading.Thread(target=pool.get, args=('k',)) for _ in range(3)]
    for thread in threads:
        thread.start()
    check(entered.wait(1), 'two commands run at once')
    time.sleep(0.05)
    check(current['peak'] == 2, 'the pool does not open more sockets than its cap')
    hold.set()
    for thread in threads:
        thread.join(2)
        check(not thread.is_alive(), 'a queued command runs after a socket is free')


def test_checkout_timeout():
    hold = threading.Event()
    entered = threading.Event()

    class Holding(object):
        def get(self, key):
            entered.set()
            hold.wait(2)
            return b'v'

        def close(self):
            pass

    pool = MemcachePool(
        ('127.0.0.1', 11211),
        max_size=1,
        checkout_timeout=0.15,
        idle_timeout=30,
        client_factory=Holding,
    )
    thread = threading.Thread(target=pool.get, args=('k',))
    thread.start()
    check(entered.wait(1), 'the only socket is checked out')
    try:
        pool.get('k')
        check(False, 'a full pool raises instead of waiting forever')
    except MemcachePoolExhausted:
        check(True, 'a full pool raises instead of waiting forever')
    hold.set()
    thread.join(2)


def main():
    for test in (test_retries_broken_pipe, test_retries_unexpected_close,
                 test_does_not_retry_logic_errors,
                 test_set_waits_for_reply, test_idle_socket_is_dropped,
                 test_pool_waits_instead_of_failing, test_checkout_timeout):
        test()

    print('')
    print('{} ({} failures)'.format('FAILED' if failures else 'PASSED', len(failures)))
    return 1 if failures else 0


if __name__ == '__main__':
    sys.exit(main())
