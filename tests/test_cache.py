import httplib2
import mock
import os
import shutil
import socket
import sys
import tests
from six.moves import http_client
from six.moves import urllib


dummy_url = 'http://127.0.0.1:1'


def get_cache_path():
    default = './_httplib2_test_cache'
    path = os.environ.get('httplib2_test_cache_path') or default
    if os.path.exists(path):
        shutil.rmtree(path)
    return path


def test_GetOnlyIfCachedCacheHit():
    # Test that can do a GET with cache and 'only-if-cached'
    http = httplib2.Http(cache=get_cache_path())
    with tests.server_const_http(add_etag=True) as uri:
        http.request(uri, "GET")
        response, content = http.request(uri, "GET", headers={'cache-control': 'only-if-cached'})
    assert response.fromcache
    assert response.status == 200


def test_GetOnlyIfCachedCacheMiss():
    # Test that can do a GET with no cache with 'only-if-cached'
    http = httplib2.Http(cache=get_cache_path())
    with tests.server_const_http(add_etag=True) as uri:
        response, content = http.request(uri, "GET", headers={'cache-control': 'only-if-cached'})
    assert not response.fromcache
    assert response.status == 504


def test_GetOnlyIfCachedNoCacheAtAll():
    # Test that can do a GET with no cache with 'only-if-cached'
    # Of course, there might be an intermediary beyond us
    # that responds to the 'only-if-cached', so this
    # test can't really be guaranteed to pass.
    http = httplib2.Http()
    with tests.server_const_http(add_etag=True) as uri:
        response, content = http.request(uri, "GET", headers={'cache-control': 'only-if-cached'})
    assert not response.fromcache
    assert response.status == 504
