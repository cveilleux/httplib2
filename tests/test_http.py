import httplib2
import mock
import socket
import sys
import tests
from six.moves import http_client, urllib


dummy_url = 'http://127.0.0.1:1'


def test_ipv6():
    # Even if IPv6 isn't installed on a machine it should just raise socket.error
    try:
        httplib2.Http().request('http://[::1]/')
    except socket.gaierror:
        assert False, 'should get the address family right for IPv6'
    except socket.error:
        pass


def test_ipv6_ssl():
    skip_types = (socket.error,)
    if sys.version_info < (3,):
        skip_types += (httplib2.CertificateHostnameMismatch,)
    try:
        httplib2.Http().request('https://[::1]/')
    except socket.gaierror:
        assert False, 'should get the address family right for IPv6'
    except skip_types:
        pass


def test_connection_type():
    http = httplib2.Http()
    http.force_exception_to_status_code = False
    response, content = http.request(dummy_url, connection_type=tests.MockHTTPConnection)
    assert response['content-location'] == dummy_url
    assert content == b'the body'


def test_bad_status_line_retry():
    http = httplib2.Http()
    old_retries = httplib2.RETRIES
    httplib2.RETRIES = 1
    http.force_exception_to_status_code = False
    try:
        response, content = http.request(dummy_url, connection_type=tests.MockHTTPBadStatusConnection)
    except http_client.BadStatusLine:
        assert tests.MockHTTPBadStatusConnection.num_calls == 2
    httplib2.RETRIES = old_retries


def test_unknown_server():
    http = httplib2.Http()
    http.force_exception_to_status_code = False
    with tests.assert_raises(httplib2.ServerNotFoundError):
        with mock.patch('socket.socket.connect', side_effect=socket.gaierror):
            http.request("http://no-such-hostname./")

    # Now test with exceptions turned off
    http.force_exception_to_status_code = True
    response, content = http.request("http://no-such-hostname./")
    assert response['content-type'] == 'text/plain'
    assert content.startswith(b"Unable to find")
    assert response.status == 400


def test_connection_refused():
    http = httplib2.Http()
    http.force_exception_to_status_code = False
    with tests.assert_raises(socket.error):
        http.request(dummy_url)

    # Now test with exceptions turned off
    http.force_exception_to_status_code = True
    response, content = http.request(dummy_url)
    assert response['content-type'] == 'text/plain'
    assert (b"Connection refused" in content or b"actively refused" in content)
    assert response.status == 400


def test_get_iri():
    http = httplib2.Http()
    query = u'?a=\N{CYRILLIC CAPITAL LETTER DJE}'
    with tests.server_reflect() as uri:
        response, content = http.request(uri + query, "GET")
    d = dict(tuple(x.split(b"=", 1)) for x in content.strip().split(b"\n"))
    assert b'uri' in d
    assert b'a=%D0%82' in d[b'uri']


def test_get_is_default_method():
    # Test that GET is the default method
    http = httplib2.Http()
    with tests.server_reflect() as uri:
        response, content = http.request(uri)
    assert response['request-method'] == "GET"


def test_different_methods():
    # Test that all methods can be used
    http = httplib2.Http()
    methods = ["GET", "PUT", "DELETE", "POST", "unknown"]
    with tests.server_reflect(accept_count=len(methods)) as uri:
        for method in methods:
            response, content = http.request(uri, method, body=b" ")
            assert response['request-method'] == method


def test_head_read():
    # Test that we don't try to read the response of a HEAD request
    # since httplib blocks response.read() for HEAD requests.
    http = httplib2.Http()
    respond_with = b'HTTP/1.0 200 OK\r\ncontent-length: 14\r\n\r\nnon-empty-body'
    with tests.server_const_bytes(respond_with) as uri:
        response, content = http.request(uri, "HEAD")
    assert response.status == 200
    assert content == b""


def test_get_no_cache():
    # Test that can do a GET w/o the cache turned on.
    http = httplib2.Http()
    with tests.server_const_http() as uri:
        response, content = http.request(uri, "GET")
    assert response.status == 200
    assert response.previous is None


def test_UserAgent():
    # Test that we provide a default user-agent
    http = httplib2.Http()
    with tests.server_reflect() as uri:
        response, content = http.request(uri, 'GET')
    assert response.status == 200
    assert b'header-user-agent: Python-httplib2/' in content


def test_UserAgentNonDefault():
    # Test that the default user-agent can be over-ridden
    http = httplib2.Http()
    with tests.server_reflect() as uri:
        response, content = http.request(uri, 'GET', headers={'User-Agent': 'fred/1.0'})
    assert response.status == 200
    assert b'header-user-agent: fred/1.0\n' in content


def test_Get300WithLocation():
    # Test the we automatically follow 300 redirects if a Location: header is provided
    http = httplib2.Http()
    final_content = b'This is the final destination.\n'
    routes = {
        '/final': tests.http_response_bytes(body=final_content),
        '': tests.http_response_bytes(status='300 Multiple Choices', headers={'location': '/final'}),
    }
    with tests.server_route(routes, accept_count=2) as uri:
        response, content = http.request(uri, 'GET')
    assert response.status == 200
    assert content == final_content
    assert response.previous.status == 300
    assert not response.previous.fromcache

    # Confirm that the intermediate 300 is not cached
    with tests.server_route(routes, accept_count=2) as uri:
        response, content = http.request(uri, 'GET')
    assert response.status == 200
    assert content == final_content
    assert response.previous.status == 300
    assert not response.previous.fromcache


def test_Get300WithLocationNoRedirect():
    # Test the we automatically follow 300 redirects if a Location: header is provided
    http = httplib2.Http()
    http.follow_redirects = False
    with tests.server_const_http(
            status='300 Multiple Choices', headers={'location': '/final'}, body=b'redirect body',
            ) as uri:
        response, content = http.request(uri, 'GET')
    assert response.status == 300


def test_Get300WithoutLocation():
    # Not giving a Location: header in a 300 response is acceptable
    # In which case we just return the 300 response
    http = httplib2.Http()
    with tests.server_const_http(status='300 Multiple Choices', body=b'redirect body') as uri:
        response, content = http.request(uri, 'GET')
    assert response.status == 300
    assert response.previous is None
    assert content == b'redirect body'


def test_Get301():
    # Test that we automatically follow 301 redirects
    # and that we cache the 301 response
    uri = urllib.parse.urljoin(base, '301/onestep.asis')
    destination = urllib.parse.urljoin(base, '302/final-destination.txt')
    http = httplib2.Http()
    response, content = http.request(uri, 'GET')
    assert response.status == 200
    assert 'content-location' in response
    assert response['content-location'] == destination
    assert content == 'This is the final destination.\n'
    assert response.previous.status == 301
    assert not response.previous.fromcache

    response, content = http.request(uri, 'GET')
    assert response.status == 200
    assert response['content-location'] == destination
    assert content == 'This is the final destination.\n'
    assert response.previous.status == 301
    assert response.previous.fromcache


def test_Head301():
    # Test that we automatically follow 301 redirects
    uri = urllib.parse.urljoin(base, '301/onestep.asis')
    destination = urllib.parse.urljoin(base, '302/final-destination.txt')
    http = httplib2.Http()
    response, content = http.request(uri, 'HEAD')
    assert response.status == 200
    assert response.previous.status == 301
    assert not response.previous.fromcache


def test_Get301NoRedirect():
    # Test that we automatically follow 301 redirects
    # and that we cache the 301 response
    http = httplib2.Http()
    http.follow_redirects = False
    uri = urllib.parse.urljoin(base, '301/onestep.asis')
    destination = urllib.parse.urljoin(base, '302/final-destination.txt')
    response, content = http.request(uri, 'GET')
    assert response.status == 301


def test_Get302():
    # Test that we automatically follow 302 redirects
    # and that we DO NOT cache the 302 response
    uri = urllib.parse.urljoin(base, '302/onestep.asis')
    destination = urllib.parse.urljoin(base, '302/final-destination.txt')
    http = httplib2.Http()
    response, content = http.request(uri, 'GET')
    assert response.status == 200
    assert response['content-location'] == destination
    assert content == 'This is the final destination.\n'
    assert response.previous.status == 302
    assert response.previous.fromcache == False

    uri = urllib.parse.urljoin(base, '302/onestep.asis')
    response, content = http.request(uri, 'GET')
    assert response.status == 200
    assert response.fromcache == True
    assert response['content-location'] == destination
    assert content == 'This is the final destination.\n'
    assert response.previous.status == 302
    assert response.previous.fromcache == False
    assert response.previous['content-location'] == uri

    uri = urllib.parse.urljoin(base, '302/twostep.asis')

    response, content = http.request(uri, 'GET')
    assert response.status == 200
    assert response.fromcache == True
    assert content == 'This is the final destination.\n'
    assert response.previous.status == 302
    assert response.previous.fromcache == False


def test_Get302RedirectionLimit():
    # Test that we can set a lower redirection limit
    # and that we raise an exception when we exceed
    # that limit.
    http = httplib2.Http()
    http.force_exception_to_status_code = False

    uri = urllib.parse.urljoin(base, '302/twostep.asis')
    try:
        response, content = http.request(uri, 'GET', redirections = 1)
        self.fail('This should not happen')
    except httplib2.RedirectLimit:
        pass
    except Exception as e:
        self.fail('Threw wrong kind of exception ')

    # Re-run the test with out the exceptions
    http.force_exception_to_status_code = True

    response, content = http.request(uri, 'GET', redirections = 1)
    assert response.status == 500
    assert response.reason.startswith('Redirected more')
    assert '302' == response['status']
    assert content.startswith('<html>')
    assert response.previous != None


def test_Get302NoLocation():
    # Test that we throw an exception when we get
    # a 302 with no Location: header.
    http = httplib2.Http()
    http.force_exception_to_status_code = False
    uri = urllib.parse.urljoin(base, '302/no-location.asis')
    try:
        response, content = http.request(uri, 'GET')
        self.fail('Should never reach here')
    except httplib2.RedirectMissingLocation:
        pass
    except Exception as e:
        self.fail('Threw wrong kind of exception ')

    # Re-run the test with out the exceptions
    http.force_exception_to_status_code = True

    response, content = http.request(uri, 'GET')
    assert response.status == 500
    assert response.reason.startswith('Redirected but')
    assert '302' == response['status']
    assert content.startswith('This is content')
