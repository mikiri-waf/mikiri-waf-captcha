#!/usr/bin/env python3

"""
Mikiri WAF CAPTCHA
Copyright (c) Mikiri Security, LLC
Author: Romanov R.

Thread-safe pool of memcached connections for one gunicorn worker.

A worker used to keep a single socket. Memcached closes idle sockets, the
next command failed with a broken pipe, and only the command after that
succeeded. Under load that dropped captcha pages and images.

Each command checks a connection out of the pool. A dead socket is closed
and the same command runs once more on a new connection. Callers wait for a
free connection instead of failing when every connection is already in use.
"""

import socket
import threading
import time
from collections import deque

from pymemcache.client.base import Client, KeepaliveOpts
from pymemcache.exceptions import MemcacheUnexpectedCloseError

# Local memcached. A command slower than this is a dead socket: drop it and
# retry the command once.
COMMAND_TIMEOUT = 0.25
CONNECT_TIMEOUT = 0.2
# How long a caller waits when every pooled connection is already checked out.
CHECKOUT_TIMEOUT = 0.25
# Close sockets we have not used recently, before memcached drops them.
IDLE_TIMEOUT = 10
# Checked-out commands per worker. Sized so workers * POOL_SIZE stays under
# memcached's default 1024 connections on machines with dozens of cores.
POOL_SIZE = 16

# Connection errors only. A bad key or a full cache must not be retried.
_RETRYABLE = (
    MemcacheUnexpectedCloseError,
    ConnectionError,
    TimeoutError,
)


class MemcachePoolExhausted(Exception):
    """Every pooled connection is busy and none was freed in time."""


def _keepalive():
    # TCP_KEEPIDLE is Linux. Elsewhere a dead peer is handled by the idle
    # timeout and the one retry.
    if not hasattr(socket, 'TCP_KEEPIDLE'):
        return None
    return KeepaliveOpts(idle=5, intvl=1, cnt=3)


def _connect(server):
    return Client(
        server,
        connect_timeout=CONNECT_TIMEOUT,
        timeout=COMMAND_TIMEOUT,
        no_delay=True,
        # Wait for STORED. A noreply set can still be sitting in the kernel
        # buffer when another worker reads the key for the captcha image.
        default_noreply=False,
        socket_keepalive=_keepalive(),
    )


class MemcachePool(object):
    """Pool of pymemcache clients. Safe to call from several threads."""

    def __init__(self, server, max_size=POOL_SIZE, checkout_timeout=CHECKOUT_TIMEOUT,
                 idle_timeout=IDLE_TIMEOUT, client_factory=None):
        self._max_size = max_size
        self._checkout_timeout = checkout_timeout
        self._idle_timeout = idle_timeout
        self._client_factory = client_factory or (lambda: _connect(server))
        self._free = deque()
        self._size = 0
        self._cv = threading.Condition()

    def get(self, key):
        return self._call(lambda client: client.get(key))

    def set(self, key, value, ttl):
        # noreply is explicit: the session has to be stored before the page
        # that points at it is sent to the browser.
        return self._call(lambda client: client.set(key, value, expire=ttl, noreply=False))

    def delete(self, key):
        return self._call(lambda client: client.delete(key, noreply=False))

    def _call(self, fn):
        error = None
        for _attempt in range(2):
            client = self._acquire()
            # Drop the socket on any failure. A protocol error can leave it
            # out of sync, and a broken pipe must not go back into the pool.
            broken = True
            try:
                result = fn(client)
                broken = False
                return result
            except _RETRYABLE as exc:
                error = exc
            finally:
                self._release(client, broken)
        raise error

    def _acquire(self):
        deadline = time.monotonic() + self._checkout_timeout
        while True:
            with self._cv:
                expired = self._expire_locked()
                if self._free:
                    client, _ts = self._free.popleft()
                    action = 'reuse'
                elif self._size < self._max_size:
                    self._size += 1
                    client = None
                    action = 'new'
                else:
                    client = None
                    remaining = deadline - time.monotonic()
                    if remaining <= 0:
                        action = 'timeout'
                    else:
                        self._cv.wait(remaining)
                        action = 'wait'
            self._close_all(expired)
            if action == 'reuse':
                return client
            if action == 'new':
                try:
                    return self._client_factory()
                except BaseException:
                    with self._cv:
                        self._size -= 1
                        self._cv.notify()
                    raise
            if action == 'timeout':
                with self._cv:
                    self._cv.notify_all()
                raise MemcachePoolExhausted('memcached connection pool is exhausted')

    def _expire_locked(self):
        if self._idle_timeout <= 0:
            return []
        now = time.monotonic()
        expired = []
        while self._free and now - self._free[0][1] > self._idle_timeout:
            client, _ts = self._free.popleft()
            self._size -= 1
            expired.append(client)
        return expired

    def _release(self, client, broken):
        if broken:
            self._close(client)
            with self._cv:
                self._size -= 1
                self._cv.notify()
            return
        with self._cv:
            self._free.append((client, time.monotonic()))
            self._cv.notify()

    def _close_all(self, clients):
        for client in clients:
            self._close(client)

    def _close(self, client):
        try:
            client.close()
        except Exception:
            pass


def new_pool():
    return MemcachePool(('127.0.0.1', 11211))
