#!/usr/bin/env python3
"""
httplib2test

A set of unit tests for httplib2.py.

Requires Python 3.0 or later
"""

__author__ = "Joe Gregorio (joe@bitworking.org)"
__copyright__ = "Copyright 2006, Joe Gregorio"
__contributors__ = ["Mark Pilgrim"]
__license__ = "MIT"
__history__ = """ """
__version__ = "0.2 ($Rev: 118 $)"

import base64
import http.client
import httplib2
import io
import os
import pickle
import socket
import ssl
import sys
import time
import unittest
import urllib.parse

# The test resources base uri
base = 'http://bitworking.org/projects/httplib2/test/'
#base = 'http://localhost/projects/httplib2/test/'
cacheDirName = ".cache"


class _MyResponse(io.BytesIO):
    def __init__(self, body, **kwargs):
        io.BytesIO.__init__(self, body)
        self.headers = kwargs

    def items(self):
        return self.headers.items()

    def iteritems(self):
        return iter(self.headers.items())


class _MyHTTPConnection(object):
    "This class is just a mock of httplib.HTTPConnection used for testing"

    def __init__(self, host, port=None, key_file=None, cert_file=None,
                 strict=None, timeout=None, proxy_info=None):
        self.host = host
        self.port = port
        self.timeout = timeout
        self.log = ""
        self.sock = None

    def set_debuglevel(self, level):
        pass

    def connect(self):
        "Connect to a host on a given port."
        pass

    def close(self):
        pass

    def request(self, method, request_uri, body, headers):
        pass

    def getresponse(self):
        return _MyResponse(b"the body", status="200")


class _MyHTTPBadStatusConnection(object):
    "Mock of httplib.HTTPConnection that raises BadStatusLine."

    num_calls = 0

    def __init__(self, host, port=None, key_file=None, cert_file=None,
                 strict=None, timeout=None, proxy_info=None):
        self.host = host
        self.port = port
        self.timeout = timeout
        self.log = ""
        self.sock = None
        _MyHTTPBadStatusConnection.num_calls = 0

    def set_debuglevel(self, level):
        pass

    def connect(self):
        pass

    def close(self):
        pass

    def request(self, method, request_uri, body, headers):
        pass

    def getresponse(self):
        _MyHTTPBadStatusConnection.num_calls += 1
        raise http.client.BadStatusLine("")


class HttpTest(unittest.TestCase):
    def setUp(self):
        if os.path.exists(cacheDirName):
            [os.remove(os.path.join(cacheDirName, file)) for file in os.listdir(cacheDirName)]
        self.http = httplib2.Http(cacheDirName)
        self.http.clear_credentials()

    def reflector(self, content):
        return  dict( [tuple(x.split("=", 1)) for x in content.decode('utf-8').strip().split("\n")] )

try:
    import memcache
    class HttpTestMemCached(HttpTest):
        def setUp(self):
            self.cache = memcache.Client(['127.0.0.1:11211'], debug=0)
            #self.cache = memcache.Client(['10.0.0.4:11211'], debug=1)
            self.http = httplib2.Http(self.cache)
            self.cache.flush_all()
            # Not exactly sure why the sleep is needed here, but
            # if not present then some unit tests that rely on caching
            # fail. Memcached seems to lose some sets immediately
            # after a flush_all if the set is to a value that
            # was previously cached. (Maybe the flush is handled async?)
            time.sleep(1)
            self.http.clear_credentials()
except:
    pass



# ------------------------------------------------------------------------

