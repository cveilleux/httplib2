import httplib2
import pytest
import tests
import time


dummy_url = 'http://127.0.0.1:1'


def test_GetOnlyIfCachedCacheHit():
    # Test that can do a GET with cache and 'only-if-cached'
    http = httplib2.Http(cache=tests.get_cache_path())
    with tests.server_const_http(add_etag=True) as uri:
        http.request(uri, "GET")
        response, content = http.request(uri, "GET", headers={'cache-control': 'only-if-cached'})
    assert response.fromcache
    assert response.status == 200


def test_GetOnlyIfCachedCacheMiss():
    # Test that can do a GET with no cache with 'only-if-cached'
    http = httplib2.Http(cache=tests.get_cache_path())
    with tests.server_const_http(accept_count=0) as uri:
        response, content = http.request(uri, "GET", headers={'cache-control': 'only-if-cached'})
    assert not response.fromcache
    assert response.status == 504


def test_GetOnlyIfCachedNoCacheAtAll():
    # Test that can do a GET with no cache with 'only-if-cached'
    # Of course, there might be an intermediary beyond us
    # that responds to the 'only-if-cached', so this
    # test can't really be guaranteed to pass.
    http = httplib2.Http()
    with tests.server_const_http(accept_count=0) as uri:
        response, content = http.request(uri, "GET", headers={'cache-control': 'only-if-cached'})
    assert not response.fromcache
    assert response.status == 504


@pytest.mark.skip(reason='was commented in legacy code')
def test_TODO_vary_no():
    pass
    # when there is no vary, a different Accept header (e.g.) should not
    # impact if the cache is used
    # test that the vary header is not sent
    # uri = urllib.parse.urljoin(base, "vary/no-vary.asis")
    # response, content = http.request(uri, "GET", headers={'Accept': 'text/plain'})
    # assert response.status == 200
    # assert 'vary' not in response
    #
    # response, content = http.request(uri, "GET", headers={'Accept': 'text/plain'})
    # assert response.status == 200
    # assert response.fromcache, "Should be from cache"
    #
    # response, content = http.request(uri, "GET", headers={'Accept': 'text/html'})
    # assert response.status == 200
    # assert response.fromcache, "Should be from cache"


def test_VaryHeaderSimple():
    """
    RFC 2616 13.6
    When the cache receives a subsequent request whose Request-URI
    specifies one or more cache entries including a Vary header field,
    the cache MUST NOT use such a cache entry to construct a response
    to the new request unless all of the selecting request-headers
    present in the new request match the corresponding stored
    request-headers in the original request.
    """
    # test that the vary header is sent
    http = httplib2.Http(cache=tests.get_cache_path())
    response = tests.http_response_bytes(
        headers={'vary': 'Accept', 'cache-control': 'max-age=300'},
        add_date=True,
    )
    with tests.server_const_bytes(response, accept_count=3) as uri:
        response, content = http.request(uri, "GET", headers={'accept': 'text/plain'})
        assert response.status == 200
        assert 'vary' in response

        # get the resource again, from the cache since accept header in this
        # request is the same as the request
        response, content = http.request(uri, "GET", headers={'Accept': 'text/plain'})
        assert response.status == 200
        assert response.fromcache, "Should be from cache"

        # get the resource again, not from cache since Accept headers does not match
        response, content = http.request(uri, "GET", headers={'Accept': 'text/html'})
        assert response.status == 200
        assert not response.fromcache, "Should not be from cache"

        # get the resource again, without any Accept header, so again no match
        response, content = http.request(uri, "GET")
        assert response.status == 200
        assert not response.fromcache, "Should not be from cache"


def test_VaryHeaderDouble():
    http = httplib2.Http(cache=tests.get_cache_path())
    response = tests.http_response_bytes(
        headers={'vary': 'Accept, Accept-Language', 'cache-control': 'max-age=300'},
        add_date=True,
    )
    with tests.server_const_bytes(response, accept_count=3) as uri:
        response, content = http.request(uri, "GET", headers={
            'Accept': 'text/plain',
            'Accept-Language': 'da, en-gb;q=0.8, en;q=0.7',
        })
        assert response.status == 200
        assert 'vary' in response

        # we are from cache
        response, content = http.request(uri, "GET", headers={
            'Accept': 'text/plain', 'Accept-Language': 'da, en-gb;q=0.8, en;q=0.7'})
        assert response.fromcache, "Should be from cache"

        response, content = http.request(uri, "GET", headers={'Accept': 'text/plain'})
        assert response.status == 200
        assert not response.fromcache

        # get the resource again, not from cache, varied headers don't match exact
        response, content = http.request(uri, "GET", headers={'Accept-Language': 'da'})
        assert response.status == 200
        assert not response.fromcache, "Should not be from cache"


def test_VaryUnusedHeader():
    http = httplib2.Http(cache=tests.get_cache_path())
    response = tests.http_response_bytes(
        headers={'vary': 'X-No-Such-Header', 'cache-control': 'max-age=300'},
        add_date=True,
    )
    with tests.server_const_bytes(response, accept_count=1) as uri:
        # A header's value is not considered to vary if it's not used at all.
        response, content = http.request(uri, "GET", headers={'Accept': 'text/plain'})
        assert response.status == 200
        assert 'vary' in response

        # we are from cache
        response, content = http.request(uri, "GET", headers={'Accept': 'text/plain'})
        assert response.fromcache, "Should be from cache"


def test_GetCacheControlNoCache():
    # Test Cache-Control: no-cache on requests
    uri = urllib.parse.urljoin(base, "304/test_etag.txt")
    response, content = http.request(uri, "GET", headers = {'accept-encoding': 'identity'})
    assertNotEqual(response['etag'], "")
    response, content = http.request(uri, "GET", headers = {'accept-encoding': 'identity'})
    assert response.status == 200
    assert response.fromcache

    response, content = http.request(uri, "GET", headers = {'accept-encoding': 'identity', 'Cache-Control': 'no-cache'})
    assert response.status == 200
    assert not response.fromcache


def test_GetCacheControlPragmaNoCache():
    # Test Pragma: no-cache on requests
    uri = urllib.parse.urljoin(base, "304/test_etag.txt")
    response, content = http.request(uri, "GET", headers = {'accept-encoding': 'identity'})
    assertNotEqual(response['etag'], "")
    response, content = http.request(uri, "GET", headers = {'accept-encoding': 'identity'})
    assert response.status == 200
    assert response.fromcache

    response, content = http.request(uri, "GET", headers = {'accept-encoding': 'identity', 'Pragma': 'no-cache'})
    assert response.status == 200
    assert not response.fromcache


def test_GetCacheControlNoStoreRequest():
    # A no-store request means that the response should not be stored.
    uri = urllib.parse.urljoin(base, "304/test_etag.txt")

    response, content = http.request(uri, "GET", headers={'Cache-Control': 'no-store'})
    assert response.status == 200
    assert not response.fromcache

    response, content = http.request(uri, "GET", headers={'Cache-Control': 'no-store'})
    assert response.status == 200
    assert not response.fromcache


def test_GetCacheControlNoStoreResponse():
    # A no-store response means that the response should not be stored.
    uri = urllib.parse.urljoin(base, "no-store/no-store.asis")

    response, content = http.request(uri, "GET")
    assert response.status == 200
    assert not response.fromcache

    response, content = http.request(uri, "GET")
    assert response.status == 200
    assert not response.fromcache


def test_GetCacheControlNoCacheNoStoreRequest():
    # Test that a no-store, no-cache clears the entry from the cache
    # even if it was cached previously.
    uri = urllib.parse.urljoin(base, "304/test_etag.txt")

    response, content = http.request(uri, "GET")
    response, content = http.request(uri, "GET")
    assert response.fromcache
    response, content = http.request(uri, "GET", headers={'Cache-Control': 'no-store, no-cache'})
    response, content = http.request(uri, "GET", headers={'Cache-Control': 'no-store, no-cache'})
    assert response.status == 200
    assert not response.fromcache


def test_UpdateInvalidatesCache():
    # Test that calling PUT or DELETE on a
    # URI that is cache invalidates that cache.
    uri = urllib.parse.urljoin(base, "304/test_etag.txt")

    response, content = http.request(uri, "GET")
    response, content = http.request(uri, "GET")
    assert response.fromcache
    response, content = http.request(uri, "DELETE")
    assert response.status == 405

    response, content = http.request(uri, "GET")
    assert not response.fromcache


def test_UpdateUsesCachedETag():
    # Test that we natively support http://www.w3.org/1999/04/Editing/
    uri = urllib.parse.urljoin(base, "conditional-updates/test.cgi")

    response, content = http.request(uri, "GET")
    assert response.status == 200
    assert not response.fromcache
    response, content = http.request(uri, "GET")
    assert response.status == 200
    assert response.fromcache
    response, content = http.request(uri, "PUT", body="foo")
    assert response.status == 200
    response, content = http.request(uri, "PUT", body="foo")
    assert response.status == 412


def test_UpdatePatchUsesCachedETag():
    # Test that we natively support http://www.w3.org/1999/04/Editing/
    uri = urllib.parse.urljoin(base, "conditional-updates/test.cgi")

    response, content = http.request(uri, "GET")
    assert response.status == 200
    assert not response.fromcache
    response, content = http.request(uri, "GET")
    assert response.status == 200
    assert response.fromcache
    response, content = http.request(uri, "PATCH", body="foo")
    assert response.status == 200
    response, content = http.request(uri, "PATCH", body="foo")
    assert response.status == 412


def test_UpdateUsesCachedETagAndOCMethod():
    # Test that we natively support http://www.w3.org/1999/04/Editing/
    uri = urllib.parse.urljoin(base, "conditional-updates/test.cgi")

    response, content = http.request(uri, "GET")
    assert response.status == 200
    assert not response.fromcache
    response, content = http.request(uri, "GET")
    assert response.status == 200
    assert response.fromcache
    http.optimistic_concurrency_methods.append("DELETE")
    response, content = http.request(uri, "DELETE")
    assert response.status == 200


def test_UpdateUsesCachedETagOverridden():
    # Test that we natively support http://www.w3.org/1999/04/Editing/
    uri = urllib.parse.urljoin(base, "conditional-updates/test.cgi")

    response, content = http.request(uri, "GET")
    assert response.status == 200
    assert not response.fromcache
    response, content = http.request(uri, "GET")
    assert response.status == 200
    assert response.fromcache
    response, content = http.request(uri, "PUT", body="foo", headers={'if-match': 'fred'})
    assert response.status == 412


def test_ParseCacheControl():
    # Test that we can parse the Cache-Control header
    assertEqual({}, httplib2._parse_cache_control({}))
    assertEqual({'no-cache': 1}, httplib2._parse_cache_control({'cache-control': ' no-cache'}))
    cc = httplib2._parse_cache_control({'cache-control': ' no-cache, max-age = 7200'})
    assertEqual(cc['no-cache'], 1)
    assertEqual(cc['max-age'], '7200')
    cc = httplib2._parse_cache_control({'cache-control': ' , '})
    assertEqual(cc[''], 1)

    try:
        cc = httplib2._parse_cache_control({'cache-control': 'Max-age=3600;post-check=1800,pre-check=3600'})
        assert "max-age" in cc
    except:
        fail("Should not throw exception")


def test_NormalizeHeaders():
    # Test that we normalize headers to lowercase
    h = httplib2._normalize_headers({'Cache-Control': 'no-cache', 'Other': 'Stuff'})
    assert 'cache-control' in h
    assert 'other' in h
    assert h['other'] == 'Stuff'


def test_ExpirationModelTransparent():
    # Test that no-cache makes our request TRANSPARENT
    response_headers = {
        'cache-control': 'max-age=7200'
    }
    request_headers = {
        'cache-control': 'no-cache'
    }
    assertEqual("TRANSPARENT", httplib2._entry_disposition(response_headers, request_headers))


def test_MaxAgeNonNumeric():
    # Test that no-cache makes our request TRANSPARENT
    response_headers = {
        'cache-control': 'max-age=fred, min-fresh=barney'
    }
    request_headers = {
    }
    assertEqual("STALE", httplib2._entry_disposition(response_headers, request_headers))


def test_ExpirationModelNoCacheResponse():
    # The date and expires point to an entry that should be
    # FRESH, but the no-cache over-rides that.
    now = time.time()
    response_headers = {
        'date': time.strftime("%a, %d %b %Y %H:%M:%S GMT", time.gmtime(now)),
        'expires': time.strftime("%a, %d %b %Y %H:%M:%S GMT", time.gmtime(now+4)),
        'cache-control': 'no-cache'
    }
    request_headers = {
    }
    assertEqual("STALE", httplib2._entry_disposition(response_headers, request_headers))


def test_ExpirationModelStaleRequestMustReval():
    # must-revalidate forces STALE
    assertEqual("STALE", httplib2._entry_disposition({}, {'cache-control': 'must-revalidate'}))


def test_ExpirationModelStaleResponseMustReval():
    # must-revalidate forces STALE
    assertEqual("STALE", httplib2._entry_disposition({'cache-control': 'must-revalidate'}, {}))


def test_ExpirationModelFresh():
    response_headers = {
        'date': time.strftime("%a, %d %b %Y %H:%M:%S GMT", time.gmtime()),
        'cache-control': 'max-age=2'
    }
    request_headers = {
    }
    assertEqual("FRESH", httplib2._entry_disposition(response_headers, request_headers))
    time.sleep(3)
    assertEqual("STALE", httplib2._entry_disposition(response_headers, request_headers))


def test_ExpirationMaxAge0():
    response_headers = {
        'date': time.strftime("%a, %d %b %Y %H:%M:%S GMT", time.gmtime()),
        'cache-control': 'max-age=0'
    }
    request_headers = {
    }
    assertEqual("STALE", httplib2._entry_disposition(response_headers, request_headers))


def test_ExpirationModelDateAndExpires():
    now = time.time()
    response_headers = {
        'date': time.strftime("%a, %d %b %Y %H:%M:%S GMT", time.gmtime(now)),
        'expires': time.strftime("%a, %d %b %Y %H:%M:%S GMT", time.gmtime(now+2)),
    }
    request_headers = {
    }
    assertEqual("FRESH", httplib2._entry_disposition(response_headers, request_headers))
    time.sleep(3)
    assertEqual("STALE", httplib2._entry_disposition(response_headers, request_headers))


def test_ExpiresZero():
    now = time.time()
    response_headers = {
        'date': time.strftime("%a, %d %b %Y %H:%M:%S GMT", time.gmtime(now)),
        'expires': "0",
    }
    request_headers = {
    }
    assertEqual("STALE", httplib2._entry_disposition(response_headers, request_headers))


def test_ExpirationModelDateOnly():
    now = time.time()
    response_headers = {
        'date': time.strftime("%a, %d %b %Y %H:%M:%S GMT", time.gmtime(now+3)),
    }
    request_headers = {
    }
    assertEqual("STALE", httplib2._entry_disposition(response_headers, request_headers))


def test_ExpirationModelOnlyIfCached():
    response_headers = {
    }
    request_headers = {
        'cache-control': 'only-if-cached',
    }
    assertEqual("FRESH", httplib2._entry_disposition(response_headers, request_headers))


def test_ExpirationModelMaxAgeBoth():
    now = time.time()
    response_headers = {
        'date': time.strftime("%a, %d %b %Y %H:%M:%S GMT", time.gmtime(now)),
        'cache-control': 'max-age=2'
    }
    request_headers = {
        'cache-control': 'max-age=0'
    }
    assertEqual("STALE", httplib2._entry_disposition(response_headers, request_headers))


def test_ExpirationModelDateAndExpiresMinFresh1():
    now = time.time()
    response_headers = {
        'date': time.strftime("%a, %d %b %Y %H:%M:%S GMT", time.gmtime(now)),
        'expires': time.strftime("%a, %d %b %Y %H:%M:%S GMT", time.gmtime(now+2)),
    }
    request_headers = {
        'cache-control': 'min-fresh=2'
    }
    assertEqual("STALE", httplib2._entry_disposition(response_headers, request_headers))


def test_ExpirationModelDateAndExpiresMinFresh2():
    now = time.time()
    response_headers = {
        'date': time.strftime("%a, %d %b %Y %H:%M:%S GMT", time.gmtime(now)),
        'expires': time.strftime("%a, %d %b %Y %H:%M:%S GMT", time.gmtime(now+4)),
    }
    request_headers = {
        'cache-control': 'min-fresh=2'
    }
    assertEqual("FRESH", httplib2._entry_disposition(response_headers, request_headers))


# Repeat all cache tests with memcache. How?
# cache = memcache.Client(['127.0.0.1:11211'], debug=0)
# #cache = memcache.Client(['10.0.0.4:11211'], debug=1)
# http = httplib2.Http(cache)
