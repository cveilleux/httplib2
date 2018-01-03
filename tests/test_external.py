'''These tests rely on replies from public internet services

TODO: reimplement with local stubs
'''
import httplib2
import os
import ssl
import tests


def testGet301ViaHttps():
    # Google always redirects to http://google.com
    http = httplib2.Http()
    response, content = http.request("https://code.google.com/apis/", "GET")
    assert response.status == 200
    assert response.previous.status == 301


def testGetViaHttps():
    # Test that we can handle HTTPS
    http = httplib2.Http()
    response, content = http.request("https://google.com/adsense/", "GET")
    assert response.status == 200


def testGetViaHttpsSpecViolationOnLocation():
    # Test that we follow redirects through HTTPS
    # even if they violate the spec by including
    # a relative Location: header instead of an
    # absolute one.
    http = httplib2.Http()
    response, content = http.request("https://google.com/adsense", "GET")
    assert response.status == 200
    assert response.previous is not None


def testGetViaHttpsKeyCert():
    #  At this point I can only test
    #  that the key and cert files are passed in
    #  correctly to httplib. It would be nice to have
    #  a real https endpoint to test against.
    http = httplib2.Http(timeout=2)
    http.add_certificate("akeyfile", "acertfile", "bitworking.org")
    try:
        response, content = http.request("https://bitworking.org", "GET")
    except AttributeError:
        assert http.connections["https:bitworking.org"].key_file == "akeyfile"
        assert http.connections["https:bitworking.org"].cert_file == "acertfile"
    except IOError:
        # Skip on 3.2
        pass

    try:
        response, content = http.request("https://notthere.bitworking.org", "GET")
    except httplib2.ServerNotFoundError:
        assert http.connections["https:notthere.bitworking.org"].key_file is None
        assert http.connections["https:notthere.bitworking.org"].cert_file is None
    except IOError:
        # Skip on 3.2
        pass


def testSslCertValidation():
    # Test that we get an ssl.SSLError when specifying a non-existent CA
    # certs file.
    http = httplib2.Http(ca_certs='/nosuchfile')
    with tests.assert_raises(IOError):
        http.request("https://www.google.com/", "GET")

    # Test that we get a SSLHandshakeError if we try to access
    # https://www.google.com, using a CA cert file that doesn't contain
    # the CA Google uses (i.e., simulating a cert that's not signed by a
    # trusted CA).
    other_ca_certs = os.path.join(
            os.path.dirname(os.path.abspath(httplib2.__file__)),
            "test", "other_cacerts.txt")
    http = httplib2.Http(ca_certs=other_ca_certs)
    with tests.assert_raises(ssl.SSLError):
        http.request("https://www.google.com/", "GET")


def testSniHostnameValidation():
    http = httplib2.Http()
    http.request("https://google.com/", method="GET")
