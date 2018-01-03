#!/usr/bin/env python2.4
"""
httplib2test

A set of unit tests for httplib2.py.

Requires Python 2.4 or later
"""

__author__ = "Joe Gregorio (joe@bitworking.org)"
__copyright__ = "Copyright 2006, Joe Gregorio"
__contributors__ = []
__license__ = "MIT"
__history__ = """ """
__version__ = "0.1 ($Rev: 118 $)"


import StringIO
import base64
import httplib
import httplib2
import os
import pickle
import socket
import sys
import time
import unittest
import urlparse

try:
    import ssl
except ImportError:
    pass

# Python 2.3 support
if not hasattr(unittest.TestCase, 'assertTrue'):
    unittest.TestCase.assertTrue = unittest.TestCase.failUnless
    unittest.TestCase.assertFalse = unittest.TestCase.failIf

# The test resources base uri
base = 'http://bitworking.org/projects/httplib2/test/'
#base = 'http://localhost/projects/httplib2/test/'
cacheDirName = ".cache"


class _MyResponse(StringIO.StringIO):
    def __init__(self, body, **kwargs):
        StringIO.StringIO.__init__(self, body)
        self.headers = kwargs

    def iteritems(self):
        return self.headers.iteritems()


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
        return _MyResponse("the body", status="200")

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
        raise httplib.BadStatusLine("")


class HttpTest(unittest.TestCase):
    def setUp(self):
        if os.path.exists(cacheDirName):
            [os.remove(os.path.join(cacheDirName, file)) for file in os.listdir(cacheDirName)]

        if sys.version_info < (2, 6):
            disable_cert_validation = True
        else:
            disable_cert_validation = False
        self.http = httplib2.Http(
                cacheDirName,
                disable_ssl_certificate_validation=disable_cert_validation)
        self.http.clear_credentials()

#MAP-commented this out because it consistently fails
#    def testGet304EndToEnd(self):
#       # Test that end to end headers get overwritten in the cache
#        uri = urlparse.urljoin(base, "304/end2end.cgi")
#        (response, content) = self.http.request(uri, "GET")
#        self.assertNotEqual(response['etag'], "")
#        old_date = response['date']
#        time.sleep(2)
#
#        (response, content) = self.http.request(uri, "GET", headers = {'Cache-Control': 'max-age=0'})
#        # The response should be from the cache, but the Date: header should be updated.
#        new_date = response['date']
#        self.assertNotEqual(new_date, old_date)
#        self.assertEqual(response.status, 200)
#        self.assertEqual(response.fromcache, True)

    def testGet304LastModified(self):
        # Test that we can still handle a 304
        # by only using the last-modified cache validator.
        uri = urlparse.urljoin(base, "304/last-modified-only/last-modified-only.txt")
        (response, content) = self.http.request(uri, "GET")

        self.assertNotEqual(response['last-modified'], "")
        (response, content) = self.http.request(uri, "GET")
        (response, content) = self.http.request(uri, "GET")
        self.assertEqual(response.status, 200)
        self.assertEqual(response.fromcache, True)

    def testGet307(self):
        # Test that we do follow 307 redirects but
        # do not cache the 307
        uri = urlparse.urljoin(base, "307/onestep.asis")
        (response, content) = self.http.request(uri, "GET")
        self.assertEqual(response.status, 200)
        self.assertEqual(content, "This is the final destination.\n")
        self.assertEqual(response.previous.status, 307)
        self.assertEqual(response.previous.fromcache, False)

        (response, content) = self.http.request(uri, "GET")
        self.assertEqual(response.status, 200)
        self.assertEqual(response.fromcache, True)
        self.assertEqual(content, "This is the final destination.\n")
        self.assertEqual(response.previous.status, 307)
        self.assertEqual(response.previous.fromcache, False)

    def testGet410(self):
        # Test that we pass 410's through
        uri = urlparse.urljoin(base, "410/410.asis")
        (response, content) = self.http.request(uri, "GET")
        self.assertEqual(response.status, 410)

    def testVaryHeaderSimple(self):
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
        uri = urlparse.urljoin(base, "vary/accept.asis")
        (response, content) = self.http.request(uri, "GET", headers={'Accept': 'text/plain'})
        self.assertEqual(response.status, 200)
        self.assertTrue(response.has_key('vary'))

        # get the resource again, from the cache since accept header in this
        # request is the same as the request
        (response, content) = self.http.request(uri, "GET", headers={'Accept': 'text/plain'})
        self.assertEqual(response.status, 200)
        self.assertEqual(response.fromcache, True, msg="Should be from cache")

        # get the resource again, not from cache since Accept headers does not match
        (response, content) = self.http.request(uri, "GET", headers={'Accept': 'text/html'})
        self.assertEqual(response.status, 200)
        self.assertEqual(response.fromcache, False, msg="Should not be from cache")

        # get the resource again, without any Accept header, so again no match
        (response, content) = self.http.request(uri, "GET")
        self.assertEqual(response.status, 200)
        self.assertEqual(response.fromcache, False, msg="Should not be from cache")

    def testNoVary(self):
        pass
        # when there is no vary, a different Accept header (e.g.) should not
        # impact if the cache is used
        # test that the vary header is not sent
        # uri = urlparse.urljoin(base, "vary/no-vary.asis")
        # (response, content) = self.http.request(uri, "GET", headers={'Accept': 'text/plain'})
        # self.assertEqual(response.status, 200)
        # self.assertFalse(response.has_key('vary'))

        # (response, content) = self.http.request(uri, "GET", headers={'Accept': 'text/plain'})
        # self.assertEqual(response.status, 200)
        # self.assertEqual(response.fromcache, True, msg="Should be from cache")
        #
        # (response, content) = self.http.request(uri, "GET", headers={'Accept': 'text/html'})
        # self.assertEqual(response.status, 200)
        # self.assertEqual(response.fromcache, True, msg="Should be from cache")

    def testVaryHeaderDouble(self):
        uri = urlparse.urljoin(base, "vary/accept-double.asis")
        (response, content) = self.http.request(uri, "GET", headers={
            'Accept': 'text/plain', 'Accept-Language': 'da, en-gb;q=0.8, en;q=0.7'})
        self.assertEqual(response.status, 200)
        self.assertTrue(response.has_key('vary'))

        # we are from cache
        (response, content) = self.http.request(uri, "GET", headers={
            'Accept': 'text/plain', 'Accept-Language': 'da, en-gb;q=0.8, en;q=0.7'})
        self.assertEqual(response.fromcache, True, msg="Should be from cache")

        (response, content) = self.http.request(uri, "GET", headers={'Accept': 'text/plain'})
        self.assertEqual(response.status, 200)
        self.assertEqual(response.fromcache, False)

        # get the resource again, not from cache, varied headers don't match exact
        (response, content) = self.http.request(uri, "GET", headers={'Accept-Language': 'da'})
        self.assertEqual(response.status, 200)
        self.assertEqual(response.fromcache, False, msg="Should not be from cache")

    def testVaryUnusedHeader(self):
        # A header's value is not considered to vary if it's not used at all.
        uri = urlparse.urljoin(base, "vary/unused-header.asis")
        (response, content) = self.http.request(uri, "GET", headers={
            'Accept': 'text/plain'})
        self.assertEqual(response.status, 200)
        self.assertTrue(response.has_key('vary'))

        # we are from cache
        (response, content) = self.http.request(uri, "GET", headers={
            'Accept': 'text/plain',})
        self.assertEqual(response.fromcache, True, msg="Should be from cache")


    def testHeadGZip(self):
        # Test that we don't try to decompress a HEAD response
        uri = urlparse.urljoin(base, "gzip/final-destination.txt")
        (response, content) = self.http.request(uri, "HEAD")
        self.assertEqual(response.status, 200)
        self.assertNotEqual(int(response['content-length']), 0)
        self.assertEqual(content, "")

    def testGetGZip(self):
        # Test that we support gzip compression
        uri = urlparse.urljoin(base, "gzip/final-destination.txt")
        (response, content) = self.http.request(uri, "GET")
        self.assertEqual(response.status, 200)
        self.assertFalse(response.has_key('content-encoding'))
        self.assertTrue(response.has_key('-content-encoding'))
        self.assertEqual(int(response['content-length']), len("This is the final destination.\n"))
        self.assertEqual(content, "This is the final destination.\n")

    def testPostAndGZipResponse(self):
        uri = urlparse.urljoin(base, "gzip/post.cgi")
        (response, content) = self.http.request(uri, "POST", body=" ")
        self.assertEqual(response.status, 200)
        self.assertFalse(response.has_key('content-encoding'))
        self.assertTrue(response.has_key('-content-encoding'))

    def testGetGZipFailure(self):
        # Test that we raise a good exception when the gzip fails
        self.http.force_exception_to_status_code = False
        uri = urlparse.urljoin(base, "gzip/failed-compression.asis")
        try:
            (response, content) = self.http.request(uri, "GET")
            self.fail("Should never reach here")
        except httplib2.FailedToDecompressContent:
            pass
        except Exception:
            self.fail("Threw wrong kind of exception")

        # Re-run the test with out the exceptions
        self.http.force_exception_to_status_code = True

        (response, content) = self.http.request(uri, "GET")
        self.assertEqual(response.status, 500)
        self.assertTrue(response.reason.startswith("Content purported"))

    def testTimeout(self):
        self.http.force_exception_to_status_code = True
        uri = urlparse.urljoin(base, "timeout/timeout.cgi")
        try:
            import socket
            socket.setdefaulttimeout(1)
        except:
            # Don't run the test if we can't set the timeout
            return
        (response, content) = self.http.request(uri)
        self.assertEqual(response.status, 408)
        self.assertTrue(response.reason.startswith("Request Timeout"))
        self.assertTrue(content.startswith("Request Timeout"))

    def testIndividualTimeout(self):
        uri = urlparse.urljoin(base, "timeout/timeout.cgi")
        http = httplib2.Http(timeout=1)
        http.force_exception_to_status_code = True

        (response, content) = http.request(uri)
        self.assertEqual(response.status, 408)
        self.assertTrue(response.reason.startswith("Request Timeout"))
        self.assertTrue(content.startswith("Request Timeout"))


    def testHTTPSInitTimeout(self):
        c = httplib2.HTTPSConnectionWithTimeout('localhost', 80, timeout=47)
        self.assertEqual(47, c.timeout)

    def testGetDeflate(self):
        # Test that we support deflate compression
        uri = urlparse.urljoin(base, "deflate/deflated.asis")
        (response, content) = self.http.request(uri, "GET")
        self.assertEqual(response.status, 200)
        self.assertFalse(response.has_key('content-encoding'))
        self.assertEqual(int(response['content-length']), len("This is the final destination."))
        self.assertEqual(content, "This is the final destination.")

    def testGetDeflateFailure(self):
        # Test that we raise a good exception when the deflate fails
        self.http.force_exception_to_status_code = False

        uri = urlparse.urljoin(base, "deflate/failed-compression.asis")
        try:
            (response, content) = self.http.request(uri, "GET")
            self.fail("Should never reach here")
        except httplib2.FailedToDecompressContent:
            pass
        except Exception:
            self.fail("Threw wrong kind of exception")

        # Re-run the test with out the exceptions
        self.http.force_exception_to_status_code = True

        (response, content) = self.http.request(uri, "GET")
        self.assertEqual(response.status, 500)
        self.assertTrue(response.reason.startswith("Content purported"))

    def testGetDuplicateHeaders(self):
        # Test that duplicate headers get concatenated via ','
        uri = urlparse.urljoin(base, "duplicate-headers/multilink.asis")
        (response, content) = self.http.request(uri, "GET")
        self.assertEqual(response.status, 200)
        self.assertEqual(content, "This is content\n")
        self.assertEqual(response['link'].split(",")[0], '<http://bitworking.org>; rel="home"; title="BitWorking"')

    def testGetCacheControlNoCache(self):
        # Test Cache-Control: no-cache on requests
        uri = urlparse.urljoin(base, "304/test_etag.txt")
        (response, content) = self.http.request(uri, "GET", headers= {'accept-encoding': 'identity'})
        self.assertNotEqual(response['etag'], "")
        (response, content) = self.http.request(uri, "GET", headers= {'accept-encoding': 'identity'})
        self.assertEqual(response.status, 200)
        self.assertEqual(response.fromcache, True)

        (response, content) = self.http.request(uri, "GET", headers={'accept-encoding': 'identity', 'Cache-Control': 'no-cache'})
        self.assertEqual(response.status, 200)
        self.assertEqual(response.fromcache, False)

    def testGetCacheControlPragmaNoCache(self):
        # Test Pragma: no-cache on requests
        uri = urlparse.urljoin(base, "304/test_etag.txt")
        (response, content) = self.http.request(uri, "GET", headers= {'accept-encoding': 'identity'})
        self.assertNotEqual(response['etag'], "")
        (response, content) = self.http.request(uri, "GET", headers= {'accept-encoding': 'identity'})
        self.assertEqual(response.status, 200)
        self.assertEqual(response.fromcache, True)

        (response, content) = self.http.request(uri, "GET", headers={'accept-encoding': 'identity', 'Pragma': 'no-cache'})
        self.assertEqual(response.status, 200)
        self.assertEqual(response.fromcache, False)

    def testGetCacheControlNoStoreRequest(self):
        # A no-store request means that the response should not be stored.
        uri = urlparse.urljoin(base, "304/test_etag.txt")

        (response, content) = self.http.request(uri, "GET", headers={'Cache-Control': 'no-store'})
        self.assertEqual(response.status, 200)
        self.assertEqual(response.fromcache, False)

        (response, content) = self.http.request(uri, "GET", headers={'Cache-Control': 'no-store'})
        self.assertEqual(response.status, 200)
        self.assertEqual(response.fromcache, False)

    def testGetCacheControlNoStoreResponse(self):
        # A no-store response means that the response should not be stored.
        uri = urlparse.urljoin(base, "no-store/no-store.asis")

        (response, content) = self.http.request(uri, "GET")
        self.assertEqual(response.status, 200)
        self.assertEqual(response.fromcache, False)

        (response, content) = self.http.request(uri, "GET")
        self.assertEqual(response.status, 200)
        self.assertEqual(response.fromcache, False)

    def testGetCacheControlNoCacheNoStoreRequest(self):
        # Test that a no-store, no-cache clears the entry from the cache
        # even if it was cached previously.
        uri = urlparse.urljoin(base, "304/test_etag.txt")

        (response, content) = self.http.request(uri, "GET")
        (response, content) = self.http.request(uri, "GET")
        self.assertEqual(response.fromcache, True)
        (response, content) = self.http.request(uri, "GET", headers={'Cache-Control': 'no-store, no-cache'})
        (response, content) = self.http.request(uri, "GET", headers={'Cache-Control': 'no-store, no-cache'})
        self.assertEqual(response.status, 200)
        self.assertEqual(response.fromcache, False)

    def testUpdateInvalidatesCache(self):
        # Test that calling PUT or DELETE on a
        # URI that is cache invalidates that cache.
        uri = urlparse.urljoin(base, "304/test_etag.txt")

        (response, content) = self.http.request(uri, "GET")
        (response, content) = self.http.request(uri, "GET")
        self.assertEqual(response.fromcache, True)
        (response, content) = self.http.request(uri, "DELETE")
        self.assertEqual(response.status, 405)

        (response, content) = self.http.request(uri, "GET")
        self.assertEqual(response.fromcache, False)

    def testUpdateUsesCachedETag(self):
        # Test that we natively support http://www.w3.org/1999/04/Editing/
        uri = urlparse.urljoin(base, "conditional-updates/test.cgi")

        (response, content) = self.http.request(uri, "GET")
        self.assertEqual(response.status, 200)
        self.assertEqual(response.fromcache, False)
        (response, content) = self.http.request(uri, "GET")
        self.assertEqual(response.status, 200)
        self.assertEqual(response.fromcache, True)
        (response, content) = self.http.request(uri, "PUT", body="foo")
        self.assertEqual(response.status, 200)
        (response, content) = self.http.request(uri, "PUT", body="foo")
        self.assertEqual(response.status, 412)

    def testUpdatePatchUsesCachedETag(self):
        # Test that we natively support http://www.w3.org/1999/04/Editing/
        uri = urlparse.urljoin(base, "conditional-updates/test.cgi")

        (response, content) = self.http.request(uri, "GET")
        self.assertEqual(response.status, 200)
        self.assertEqual(response.fromcache, False)
        (response, content) = self.http.request(uri, "GET")
        self.assertEqual(response.status, 200)
        self.assertEqual(response.fromcache, True)
        (response, content) = self.http.request(uri, "PATCH", body="foo")
        self.assertEqual(response.status, 200)
        (response, content) = self.http.request(uri, "PATCH", body="foo")
        self.assertEqual(response.status, 412)


    def testUpdateUsesCachedETagAndOCMethod(self):
        # Test that we natively support http://www.w3.org/1999/04/Editing/
        uri = urlparse.urljoin(base, "conditional-updates/test.cgi")

        (response, content) = self.http.request(uri, "GET")
        self.assertEqual(response.status, 200)
        self.assertEqual(response.fromcache, False)
        (response, content) = self.http.request(uri, "GET")
        self.assertEqual(response.status, 200)
        self.assertEqual(response.fromcache, True)
        self.http.optimistic_concurrency_methods.append("DELETE")
        (response, content) = self.http.request(uri, "DELETE")
        self.assertEqual(response.status, 200)


    def testUpdateUsesCachedETagOverridden(self):
        # Test that we natively support http://www.w3.org/1999/04/Editing/
        uri = urlparse.urljoin(base, "conditional-updates/test.cgi")

        (response, content) = self.http.request(uri, "GET")
        self.assertEqual(response.status, 200)
        self.assertEqual(response.fromcache, False)
        (response, content) = self.http.request(uri, "GET")
        self.assertEqual(response.status, 200)
        self.assertEqual(response.fromcache, True)
        (response, content) = self.http.request(uri, "PUT", body="foo", headers={'if-match': 'fred'})
        self.assertEqual(response.status, 412)

    def testBasicAuth(self):
        # Test Basic Authentication
        uri = urlparse.urljoin(base, "basic/file.txt")
        (response, content) = self.http.request(uri, "GET")
        self.assertEqual(response.status, 401)

        uri = urlparse.urljoin(base, "basic/")
        (response, content) = self.http.request(uri, "GET")
        self.assertEqual(response.status, 401)

        self.http.add_credentials('joe', 'password')
        (response, content) = self.http.request(uri, "GET")
        self.assertEqual(response.status, 200)

        uri = urlparse.urljoin(base, "basic/file.txt")
        (response, content) = self.http.request(uri, "GET")
        self.assertEqual(response.status, 200)

    def testBasicAuthWithDomain(self):
        # Test Basic Authentication
        uri = urlparse.urljoin(base, "basic/file.txt")
        (response, content) = self.http.request(uri, "GET")
        self.assertEqual(response.status, 401)

        uri = urlparse.urljoin(base, "basic/")
        (response, content) = self.http.request(uri, "GET")
        self.assertEqual(response.status, 401)

        self.http.add_credentials('joe', 'password', "example.org")
        (response, content) = self.http.request(uri, "GET")
        self.assertEqual(response.status, 401)

        uri = urlparse.urljoin(base, "basic/file.txt")
        (response, content) = self.http.request(uri, "GET")
        self.assertEqual(response.status, 401)

        domain = urlparse.urlparse(base)[1]
        self.http.add_credentials('joe', 'password', domain)
        (response, content) = self.http.request(uri, "GET")
        self.assertEqual(response.status, 200)

        uri = urlparse.urljoin(base, "basic/file.txt")
        (response, content) = self.http.request(uri, "GET")
        self.assertEqual(response.status, 200)






    def testBasicAuthTwoDifferentCredentials(self):
        # Test Basic Authentication with multiple sets of credentials
        uri = urlparse.urljoin(base, "basic2/file.txt")
        (response, content) = self.http.request(uri, "GET")
        self.assertEqual(response.status, 401)

        uri = urlparse.urljoin(base, "basic2/")
        (response, content) = self.http.request(uri, "GET")
        self.assertEqual(response.status, 401)

        self.http.add_credentials('fred', 'barney')
        (response, content) = self.http.request(uri, "GET")
        self.assertEqual(response.status, 200)

        uri = urlparse.urljoin(base, "basic2/file.txt")
        (response, content) = self.http.request(uri, "GET")
        self.assertEqual(response.status, 200)

    def testBasicAuthNested(self):
        # Test Basic Authentication with resources
        # that are nested
        uri = urlparse.urljoin(base, "basic-nested/")
        (response, content) = self.http.request(uri, "GET")
        self.assertEqual(response.status, 401)

        uri = urlparse.urljoin(base, "basic-nested/subdir")
        (response, content) = self.http.request(uri, "GET")
        self.assertEqual(response.status, 401)

        # Now add in credentials one at a time and test.
        self.http.add_credentials('joe', 'password')

        uri = urlparse.urljoin(base, "basic-nested/")
        (response, content) = self.http.request(uri, "GET")
        self.assertEqual(response.status, 200)

        uri = urlparse.urljoin(base, "basic-nested/subdir")
        (response, content) = self.http.request(uri, "GET")
        self.assertEqual(response.status, 401)

        self.http.add_credentials('fred', 'barney')

        uri = urlparse.urljoin(base, "basic-nested/")
        (response, content) = self.http.request(uri, "GET")
        self.assertEqual(response.status, 200)

        uri = urlparse.urljoin(base, "basic-nested/subdir")
        (response, content) = self.http.request(uri, "GET")
        self.assertEqual(response.status, 200)

    def testDigestAuth(self):
        # Test that we support Digest Authentication
        uri = urlparse.urljoin(base, "digest/")
        (response, content) = self.http.request(uri, "GET")
        self.assertEqual(response.status, 401)

        self.http.add_credentials('joe', 'password')
        (response, content) = self.http.request(uri, "GET")
        self.assertEqual(response.status, 200)

        uri = urlparse.urljoin(base, "digest/file.txt")
        (response, content) = self.http.request(uri, "GET")

    def testDigestAuthNextNonceAndNC(self):
        # Test that if the server sets nextnonce that we reset
        # the nonce count back to 1
        uri = urlparse.urljoin(base, "digest/file.txt")
        self.http.add_credentials('joe', 'password')
        (response, content) = self.http.request(uri, "GET", headers = {"cache-control":"no-cache"})
        info = httplib2._parse_www_authenticate(response, 'authentication-info')
        self.assertEqual(response.status, 200)
        (response, content) = self.http.request(uri, "GET", headers = {"cache-control":"no-cache"})
        info2 = httplib2._parse_www_authenticate(response, 'authentication-info')
        self.assertEqual(response.status, 200)

        if info.has_key('nextnonce'):
            self.assertEqual(info2['nc'], 1)

    def testDigestAuthStale(self):
        # Test that we can handle a nonce becoming stale
        uri = urlparse.urljoin(base, "digest-expire/file.txt")
        self.http.add_credentials('joe', 'password')
        (response, content) = self.http.request(uri, "GET", headers = {"cache-control":"no-cache"})
        info = httplib2._parse_www_authenticate(response, 'authentication-info')
        self.assertEqual(response.status, 200)

        time.sleep(3)
        # Sleep long enough that the nonce becomes stale

        (response, content) = self.http.request(uri, "GET", headers = {"cache-control":"no-cache"})
        self.assertFalse(response.fromcache)
        self.assertTrue(response._stale_digest)
        info3 = httplib2._parse_www_authenticate(response, 'authentication-info')
        self.assertEqual(response.status, 200)

    def reflector(self, content):
        return  dict( [tuple(x.split("=", 1)) for x in content.strip().split("\n")] )

    def testReflector(self):
        uri = urlparse.urljoin(base, "reflector/reflector.cgi")
        (response, content) = self.http.request(uri, "GET")
        d = self.reflector(content)
        self.assertTrue(d.has_key('HTTP_USER_AGENT'))

    def testConnectionClose(self):
        uri = "http://www.google.com/"
        (response, content) = self.http.request(uri, "GET")
        for c in self.http.connections.values():
            self.assertNotEqual(None, c.sock)
        (response, content) = self.http.request(uri, "GET", headers={"connection": "close"})
        for c in self.http.connections.values():
            self.assertEqual(None, c.sock)

    def testPickleHttp(self):
        pickled_http = pickle.dumps(self.http)
        new_http = pickle.loads(pickled_http)

        self.assertEqual(sorted(new_http.__dict__.keys()),
                         sorted(self.http.__dict__.keys()))
        for key in new_http.__dict__:
            if key in ('certificates', 'credentials'):
                self.assertEqual(new_http.__dict__[key].credentials,
                                 self.http.__dict__[key].credentials)
            elif key == 'cache':
                self.assertEqual(new_http.__dict__[key].cache,
                                 self.http.__dict__[key].cache)
            else:
                self.assertEqual(new_http.__dict__[key],
                                 self.http.__dict__[key])

    def testPickleHttpWithConnection(self):
        self.http.request('http://bitworking.org',
                          connection_type=_MyHTTPConnection)
        pickled_http = pickle.dumps(self.http)
        new_http = pickle.loads(pickled_http)

        self.assertEqual(self.http.connections.keys(), ['http:bitworking.org'])
        self.assertEqual(new_http.connections, {})

    def testPickleCustomRequestHttp(self):
        def dummy_request(*args, **kwargs):
            return new_request(*args, **kwargs)
        dummy_request.dummy_attr = 'dummy_value'

        self.http.request = dummy_request
        pickled_http = pickle.dumps(self.http)
        self.assertFalse("S'request'" in pickled_http)

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

class HttpPrivateTest(unittest.TestCase):

    def testParseCacheControl(self):
        # Test that we can parse the Cache-Control header
        self.assertEqual({}, httplib2._parse_cache_control({}))
        self.assertEqual({'no-cache': 1}, httplib2._parse_cache_control({'cache-control': ' no-cache'}))
        cc = httplib2._parse_cache_control({'cache-control': ' no-cache, max-age = 7200'})
        self.assertEqual(cc['no-cache'], 1)
        self.assertEqual(cc['max-age'], '7200')
        cc = httplib2._parse_cache_control({'cache-control': ' , '})
        self.assertEqual(cc[''], 1)

        try:
            cc = httplib2._parse_cache_control({'cache-control': 'Max-age=3600;post-check=1800,pre-check=3600'})
            self.assertTrue("max-age" in cc)
        except:
            self.fail("Should not throw exception")

    def testNormalizeHeaders(self):
        # Test that we normalize headers to lowercase
        h = httplib2._normalize_headers({'Cache-Control': 'no-cache', 'Other': 'Stuff'})
        self.assertTrue(h.has_key('cache-control'))
        self.assertTrue(h.has_key('other'))
        self.assertEqual('Stuff', h['other'])

    def testExpirationModelTransparent(self):
        # Test that no-cache makes our request TRANSPARENT
        response_headers = {
            'cache-control': 'max-age=7200'
        }
        request_headers = {
            'cache-control': 'no-cache'
        }
        self.assertEqual("TRANSPARENT", httplib2._entry_disposition(response_headers, request_headers))

    def testMaxAgeNonNumeric(self):
        # Test that no-cache makes our request TRANSPARENT
        response_headers = {
            'cache-control': 'max-age=fred, min-fresh=barney'
        }
        request_headers = {
        }
        self.assertEqual("STALE", httplib2._entry_disposition(response_headers, request_headers))


    def testExpirationModelNoCacheResponse(self):
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
        self.assertEqual("STALE", httplib2._entry_disposition(response_headers, request_headers))

    def testExpirationModelStaleRequestMustReval(self):
        # must-revalidate forces STALE
        self.assertEqual("STALE", httplib2._entry_disposition({}, {'cache-control': 'must-revalidate'}))

    def testExpirationModelStaleResponseMustReval(self):
        # must-revalidate forces STALE
        self.assertEqual("STALE", httplib2._entry_disposition({'cache-control': 'must-revalidate'}, {}))

    def testExpirationModelFresh(self):
        response_headers = {
            'date': time.strftime("%a, %d %b %Y %H:%M:%S GMT", time.gmtime()),
            'cache-control': 'max-age=2'
        }
        request_headers = {
        }
        self.assertEqual("FRESH", httplib2._entry_disposition(response_headers, request_headers))
        time.sleep(3)
        self.assertEqual("STALE", httplib2._entry_disposition(response_headers, request_headers))

    def testExpirationMaxAge0(self):
        response_headers = {
            'date': time.strftime("%a, %d %b %Y %H:%M:%S GMT", time.gmtime()),
            'cache-control': 'max-age=0'
        }
        request_headers = {
        }
        self.assertEqual("STALE", httplib2._entry_disposition(response_headers, request_headers))

    def testExpirationModelDateAndExpires(self):
        now = time.time()
        response_headers = {
            'date': time.strftime("%a, %d %b %Y %H:%M:%S GMT", time.gmtime(now)),
            'expires': time.strftime("%a, %d %b %Y %H:%M:%S GMT", time.gmtime(now+2)),
        }
        request_headers = {
        }
        self.assertEqual("FRESH", httplib2._entry_disposition(response_headers, request_headers))
        time.sleep(3)
        self.assertEqual("STALE", httplib2._entry_disposition(response_headers, request_headers))

    def testExpiresZero(self):
        now = time.time()
        response_headers = {
            'date': time.strftime("%a, %d %b %Y %H:%M:%S GMT", time.gmtime(now)),
            'expires': "0",
        }
        request_headers = {
        }
        self.assertEqual("STALE", httplib2._entry_disposition(response_headers, request_headers))

    def testExpirationModelDateOnly(self):
        now = time.time()
        response_headers = {
            'date': time.strftime("%a, %d %b %Y %H:%M:%S GMT", time.gmtime(now+3)),
        }
        request_headers = {
        }
        self.assertEqual("STALE", httplib2._entry_disposition(response_headers, request_headers))

    def testExpirationModelOnlyIfCached(self):
        response_headers = {
        }
        request_headers = {
            'cache-control': 'only-if-cached',
        }
        self.assertEqual("FRESH", httplib2._entry_disposition(response_headers, request_headers))

    def testExpirationModelMaxAgeBoth(self):
        now = time.time()
        response_headers = {
            'date': time.strftime("%a, %d %b %Y %H:%M:%S GMT", time.gmtime(now)),
            'cache-control': 'max-age=2'
        }
        request_headers = {
            'cache-control': 'max-age=0'
        }
        self.assertEqual("STALE", httplib2._entry_disposition(response_headers, request_headers))

    def testExpirationModelDateAndExpiresMinFresh1(self):
        now = time.time()
        response_headers = {
            'date': time.strftime("%a, %d %b %Y %H:%M:%S GMT", time.gmtime(now)),
            'expires': time.strftime("%a, %d %b %Y %H:%M:%S GMT", time.gmtime(now+2)),
        }
        request_headers = {
            'cache-control': 'min-fresh=2'
        }
        self.assertEqual("STALE", httplib2._entry_disposition(response_headers, request_headers))

    def testExpirationModelDateAndExpiresMinFresh2(self):
        now = time.time()
        response_headers = {
            'date': time.strftime("%a, %d %b %Y %H:%M:%S GMT", time.gmtime(now)),
            'expires': time.strftime("%a, %d %b %Y %H:%M:%S GMT", time.gmtime(now+4)),
        }
        request_headers = {
            'cache-control': 'min-fresh=2'
        }
        self.assertEqual("FRESH", httplib2._entry_disposition(response_headers, request_headers))

    def testParseWWWAuthenticateEmpty(self):
        res = httplib2._parse_www_authenticate({})
        self.assertEqual(len(res.keys()), 0)

    def testParseWWWAuthenticate(self):
        # different uses of spaces around commas
        res = httplib2._parse_www_authenticate({ 'www-authenticate': 'Test realm="test realm" , foo=foo ,bar="bar", baz=baz,qux=qux'})
        self.assertEqual(len(res.keys()), 1)
        self.assertEqual(len(res['test'].keys()), 5)

        # tokens with non-alphanum
        res = httplib2._parse_www_authenticate({ 'www-authenticate': 'T*!%#st realm=to*!%#en, to*!%#en="quoted string"'})
        self.assertEqual(len(res.keys()), 1)
        self.assertEqual(len(res['t*!%#st'].keys()), 2)

        # quoted string with quoted pairs
        res = httplib2._parse_www_authenticate({ 'www-authenticate': 'Test realm="a \\"test\\" realm"'})
        self.assertEqual(len(res.keys()), 1)
        self.assertEqual(res['test']['realm'], 'a "test" realm')

    def testParseWWWAuthenticateStrict(self):
        httplib2.USE_WWW_AUTH_STRICT_PARSING = 1;
        self.testParseWWWAuthenticate();
        httplib2.USE_WWW_AUTH_STRICT_PARSING = 0;

    def testParseWWWAuthenticateBasic(self):
        res = httplib2._parse_www_authenticate({ 'www-authenticate': 'Basic realm="me"'})
        basic = res['basic']
        self.assertEqual('me', basic['realm'])

        res = httplib2._parse_www_authenticate({ 'www-authenticate': 'Basic realm="me", algorithm="MD5"'})
        basic = res['basic']
        self.assertEqual('me', basic['realm'])
        self.assertEqual('MD5', basic['algorithm'])

        res = httplib2._parse_www_authenticate({ 'www-authenticate': 'Basic realm="me", algorithm=MD5'})
        basic = res['basic']
        self.assertEqual('me', basic['realm'])
        self.assertEqual('MD5', basic['algorithm'])

    def testParseWWWAuthenticateBasic2(self):
        res = httplib2._parse_www_authenticate({ 'www-authenticate': 'Basic realm="me",other="fred" '})
        basic = res['basic']
        self.assertEqual('me', basic['realm'])
        self.assertEqual('fred', basic['other'])

    def testParseWWWAuthenticateBasic3(self):
        res = httplib2._parse_www_authenticate({ 'www-authenticate': 'Basic REAlm="me" '})
        basic = res['basic']
        self.assertEqual('me', basic['realm'])


    def testParseWWWAuthenticateDigest(self):
        res = httplib2._parse_www_authenticate({ 'www-authenticate':
                'Digest realm="testrealm@host.com", qop="auth,auth-int", nonce="dcd98b7102dd2f0e8b11d0f600bfb0c093", opaque="5ccc069c403ebaf9f0171e9517f40e41"'})
        digest = res['digest']
        self.assertEqual('testrealm@host.com', digest['realm'])
        self.assertEqual('auth,auth-int', digest['qop'])


    def testParseWWWAuthenticateMultiple(self):
        res = httplib2._parse_www_authenticate({ 'www-authenticate':
                'Digest realm="testrealm@host.com", qop="auth,auth-int", nonce="dcd98b7102dd2f0e8b11d0f600bfb0c093", opaque="5ccc069c403ebaf9f0171e9517f40e41" Basic REAlm="me" '})
        digest = res['digest']
        self.assertEqual('testrealm@host.com', digest['realm'])
        self.assertEqual('auth,auth-int', digest['qop'])
        self.assertEqual('dcd98b7102dd2f0e8b11d0f600bfb0c093', digest['nonce'])
        self.assertEqual('5ccc069c403ebaf9f0171e9517f40e41', digest['opaque'])
        basic = res['basic']
        self.assertEqual('me', basic['realm'])

    def testParseWWWAuthenticateMultiple2(self):
        # Handle an added comma between challenges, which might get thrown in if the challenges were
        # originally sent in separate www-authenticate headers.
        res = httplib2._parse_www_authenticate({ 'www-authenticate':
                'Digest realm="testrealm@host.com", qop="auth,auth-int", nonce="dcd98b7102dd2f0e8b11d0f600bfb0c093", opaque="5ccc069c403ebaf9f0171e9517f40e41", Basic REAlm="me" '})
        digest = res['digest']
        self.assertEqual('testrealm@host.com', digest['realm'])
        self.assertEqual('auth,auth-int', digest['qop'])
        self.assertEqual('dcd98b7102dd2f0e8b11d0f600bfb0c093', digest['nonce'])
        self.assertEqual('5ccc069c403ebaf9f0171e9517f40e41', digest['opaque'])
        basic = res['basic']
        self.assertEqual('me', basic['realm'])

    def testParseWWWAuthenticateMultiple3(self):
        # Handle an added comma between challenges, which might get thrown in if the challenges were
        # originally sent in separate www-authenticate headers.
        res = httplib2._parse_www_authenticate({ 'www-authenticate':
                'Digest realm="testrealm@host.com", qop="auth,auth-int", nonce="dcd98b7102dd2f0e8b11d0f600bfb0c093", opaque="5ccc069c403ebaf9f0171e9517f40e41", Basic REAlm="me", WSSE realm="foo", profile="UsernameToken"'})
        digest = res['digest']
        self.assertEqual('testrealm@host.com', digest['realm'])
        self.assertEqual('auth,auth-int', digest['qop'])
        self.assertEqual('dcd98b7102dd2f0e8b11d0f600bfb0c093', digest['nonce'])
        self.assertEqual('5ccc069c403ebaf9f0171e9517f40e41', digest['opaque'])
        basic = res['basic']
        self.assertEqual('me', basic['realm'])
        wsse = res['wsse']
        self.assertEqual('foo', wsse['realm'])
        self.assertEqual('UsernameToken', wsse['profile'])

    def testParseWWWAuthenticateMultiple4(self):
        res = httplib2._parse_www_authenticate({ 'www-authenticate':
                'Digest realm="test-real.m@host.com", qop \t=\t"\tauth,auth-int", nonce="(*)&^&$%#",opaque="5ccc069c403ebaf9f0171e9517f40e41", Basic REAlm="me", WSSE realm="foo", profile="UsernameToken"'})
        digest = res['digest']
        self.assertEqual('test-real.m@host.com', digest['realm'])
        self.assertEqual('\tauth,auth-int', digest['qop'])
        self.assertEqual('(*)&^&$%#', digest['nonce'])

    def testParseWWWAuthenticateMoreQuoteCombos(self):
        res = httplib2._parse_www_authenticate({'www-authenticate':'Digest realm="myrealm", nonce="Ygk86AsKBAA=3516200d37f9a3230352fde99977bd6d472d4306", algorithm=MD5, qop="auth", stale=true'})
        digest = res['digest']
        self.assertEqual('myrealm', digest['realm'])

    def testParseWWWAuthenticateMalformed(self):
        try:
          res = httplib2._parse_www_authenticate({'www-authenticate':'OAuth "Facebook Platform" "invalid_token" "Invalid OAuth access token."'})
          self.fail("should raise an exception")
        except httplib2.MalformedHeader:
          pass

    def testDigestObject(self):
        credentials = ('joe', 'password')
        host = None
        request_uri = '/projects/httplib2/test/digest/'
        headers = {}
        response = {
            'www-authenticate': 'Digest realm="myrealm", nonce="Ygk86AsKBAA=3516200d37f9a3230352fde99977bd6d472d4306", algorithm=MD5, qop="auth"'
        }
        content = ""

        d = httplib2.DigestAuthentication(credentials, host, request_uri, headers, response, content, None)
        d.request("GET", request_uri, headers, content, cnonce="33033375ec278a46")
        our_request = "authorization: %s" % headers['authorization']
        working_request = 'authorization: Digest username="joe", realm="myrealm", nonce="Ygk86AsKBAA=3516200d37f9a3230352fde99977bd6d472d4306", uri="/projects/httplib2/test/digest/", algorithm=MD5, response="97ed129401f7cdc60e5db58a80f3ea8b", qop=auth, nc=00000001, cnonce="33033375ec278a46"'
        self.assertEqual(our_request, working_request)

    def testDigestObjectWithOpaque(self):
        credentials = ('joe', 'password')
        host = None
        request_uri = '/projects/httplib2/test/digest/'
        headers = {}
        response = {
            'www-authenticate': 'Digest realm="myrealm", nonce="Ygk86AsKBAA=3516200d37f9a3230352fde99977bd6d472d4306", algorithm=MD5, qop="auth", opaque="atestopaque"'
        }
        content = ""

        d = httplib2.DigestAuthentication(credentials, host, request_uri, headers, response, content, None)
        d.request("GET", request_uri, headers, content, cnonce="33033375ec278a46")
        our_request = "authorization: %s" % headers['authorization']
        working_request = 'authorization: Digest username="joe", realm="myrealm", nonce="Ygk86AsKBAA=3516200d37f9a3230352fde99977bd6d472d4306", uri="/projects/httplib2/test/digest/", algorithm=MD5, response="97ed129401f7cdc60e5db58a80f3ea8b", qop=auth, nc=00000001, cnonce="33033375ec278a46", opaque="atestopaque"'
        self.assertEqual(our_request, working_request)

    def testDigestObjectStale(self):
        credentials = ('joe', 'password')
        host = None
        request_uri = '/projects/httplib2/test/digest/'
        headers = {}
        response = httplib2.Response({ })
        response['www-authenticate'] = 'Digest realm="myrealm", nonce="Ygk86AsKBAA=3516200d37f9a3230352fde99977bd6d472d4306", algorithm=MD5, qop="auth", stale=true'
        response.status = 401
        content = ""
        d = httplib2.DigestAuthentication(credentials, host, request_uri, headers, response, content, None)
        # Returns true to force a retry
        self.assertTrue( d.response(response, content) )

    def testDigestObjectAuthInfo(self):
        credentials = ('joe', 'password')
        host = None
        request_uri = '/projects/httplib2/test/digest/'
        headers = {}
        response = httplib2.Response({ })
        response['www-authenticate'] = 'Digest realm="myrealm", nonce="Ygk86AsKBAA=3516200d37f9a3230352fde99977bd6d472d4306", algorithm=MD5, qop="auth", stale=true'
        response['authentication-info'] = 'nextnonce="fred"'
        content = ""
        d = httplib2.DigestAuthentication(credentials, host, request_uri, headers, response, content, None)
        # Returns true to force a retry
        self.assertFalse( d.response(response, content) )
        self.assertEqual('fred', d.challenge['nonce'])
        self.assertEqual(1, d.challenge['nc'])

    def testWsseAlgorithm(self):
        digest = httplib2._wsse_username_token("d36e316282959a9ed4c89851497a717f", "2003-12-15T14:43:07Z", "taadtaadpstcsm")
        expected = "quR/EWLAV4xLf9Zqyw4pDmfV9OY="
        self.assertEqual(expected, digest)

    def testEnd2End(self):
        # one end to end header
        response = {'content-type': 'application/atom+xml', 'te': 'deflate'}
        end2end = httplib2._get_end2end_headers(response)
        self.assertTrue('content-type' in end2end)
        self.assertTrue('te' not in end2end)
        self.assertTrue('connection' not in end2end)

        # one end to end header that gets eliminated
        response = {'connection': 'content-type', 'content-type': 'application/atom+xml', 'te': 'deflate'}
        end2end = httplib2._get_end2end_headers(response)
        self.assertTrue('content-type' not in end2end)
        self.assertTrue('te' not in end2end)
        self.assertTrue('connection' not in end2end)

        # Degenerate case of no headers
        response = {}
        end2end = httplib2._get_end2end_headers(response)
        self.assertEquals(0, len(end2end))

        # Degenerate case of connection referrring to a header not passed in
        response = {'connection': 'content-type'}
        end2end = httplib2._get_end2end_headers(response)
        self.assertEquals(0, len(end2end))


class TestProxyInfo(unittest.TestCase):
    def setUp(self):
        self.orig_env = dict(os.environ)

    def tearDown(self):
        os.environ.clear()
        os.environ.update(self.orig_env)

    def test_from_url(self):
        pi = httplib2.proxy_info_from_url('http://myproxy.example.com')
        self.assertEquals(pi.proxy_host, 'myproxy.example.com')
        self.assertEquals(pi.proxy_port, 80)
        self.assertEquals(pi.proxy_user, None)

    def test_from_url_ident(self):
        pi = httplib2.proxy_info_from_url('http://zoidberg:fish@someproxy:99')
        self.assertEquals(pi.proxy_host, 'someproxy')
        self.assertEquals(pi.proxy_port, 99)
        self.assertEquals(pi.proxy_user, 'zoidberg')
        self.assertEquals(pi.proxy_pass, 'fish')

    def test_from_env(self):
        os.environ['http_proxy'] = 'http://myproxy.example.com:8080'
        pi = httplib2.proxy_info_from_environment()
        self.assertEquals(pi.proxy_host, 'myproxy.example.com')
        self.assertEquals(pi.proxy_port, 8080)
        self.assertEquals(pi.bypass_hosts, [])

    def test_from_env_no_proxy(self):
        os.environ['http_proxy'] = 'http://myproxy.example.com:80'
        os.environ['https_proxy'] = 'http://myproxy.example.com:81'
        os.environ['no_proxy'] = 'localhost,otherhost.domain.local'
        pi = httplib2.proxy_info_from_environment('https')
        self.assertEquals(pi.proxy_host, 'myproxy.example.com')
        self.assertEquals(pi.proxy_port, 81)
        self.assertEquals(pi.bypass_hosts, ['localhost',
            'otherhost.domain.local'])

    def test_from_env_none(self):
        os.environ.clear()
        pi = httplib2.proxy_info_from_environment()
        self.assertEquals(pi, None)

    def test_applies_to(self):
        os.environ['http_proxy'] = 'http://myproxy.example.com:80'
        os.environ['https_proxy'] = 'http://myproxy.example.com:81'
        os.environ['no_proxy'] = 'localhost,otherhost.domain.local,example.com'
        pi = httplib2.proxy_info_from_environment()
        self.assertFalse(pi.applies_to('localhost'))
        self.assertTrue(pi.applies_to('www.google.com'))
        self.assertFalse(pi.applies_to('www.example.com'))

    def test_no_proxy_star(self):
        os.environ['http_proxy'] = 'http://myproxy.example.com:80'
        os.environ['NO_PROXY'] = '*'
        pi = httplib2.proxy_info_from_environment()
        for host in ('localhost', '169.254.38.192', 'www.google.com'):
            self.assertFalse(pi.applies_to(host))

    def test_proxy_headers(self):
        headers = {'key0': 'val0', 'key1': 'val1'}
        pi = httplib2.ProxyInfo(httplib2.socks.PROXY_TYPE_HTTP, 'localhost', 1234, proxy_headers = headers)
        self.assertEquals(pi.proxy_headers, headers)

if __name__ == '__main__':
    unittest.main()
