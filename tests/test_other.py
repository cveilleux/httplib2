import httplib2
import pickle
import pytest
import socket
import sys
import tests
import time
from six.moves import urllib


@pytest.mark.skipif(
    sys.version_info <= (3,),
    reason='TODO: httplib2._convert_byte_str was defined only in python3 code version',
)
def test_other_convert_byte_str():
    with tests.assert_raises(TypeError):
        httplib2._convert_byte_str(4)
    assert httplib2._convert_byte_str(b'Hello') == 'Hello'
    assert httplib2._convert_byte_str('World') == 'World'


def test_other_reflect():
    http = httplib2.Http()
    with tests.server_reflect() as uri:
        response, content = http.request(uri + '?query', 'METHOD')
    assert response.status == 200
    assert response['request-method'] == 'METHOD'
    host = urllib.parse.urlparse(uri).netloc
    assert content.startswith('''\
method=METHOD
uri=/?query
protocol=HTTP/1.1
header-host: {host}'''.format(host=host).encode()), content


def test_other_pickle_http():
    http = httplib2.Http(cache=tests.get_cache_path())
    new_http = pickle.loads(pickle.dumps(http))

    assert tuple(sorted(new_http.__dict__)) == tuple(sorted(http.__dict__))
    assert new_http.credentials.credentials == http.credentials.credentials
    assert new_http.certificates.credentials == http.certificates.credentials
    assert new_http.cache.cache == http.cache.cache
    for key in new_http.__dict__:
        if key not in ('cache', 'certificates', 'credentials'):
            assert getattr(new_http, key) == getattr(http, key)


def test_other_pickle_http_with_connection():
    http = httplib2.Http()
    http.request('http://random-domain:81/', connection_type=tests.MockHTTPConnection)
    new_http = pickle.loads(pickle.dumps(http))
    assert tuple(http.connections) == ('http:random-domain:81',)
    assert new_http.connections == {}


def test_other_pickle_custom_request_http():
    http = httplib2.Http()
    http.request = lambda: None
    http.request.dummy_attr = 'dummy_value'
    new_http = pickle.loads(pickle.dumps(http))
    assert getattr(new_http.request, 'dummy_attr', None) is None


def test_timeout_global():
    def handler(request):
        time.sleep(0.5)
        return tests.http_response_bytes()

    try:
        socket.setdefaulttimeout(0.1)
    except Exception:
        pytest.skip('cannot set global socket timeout')
    try:
        http = httplib2.Http()
        http.force_exception_to_status_code = True
        with tests.server_request(handler) as uri:
            response, content = http.request(uri)
            assert response.status == 408
            assert response.reason.startswith("Request Timeout")
    finally:
        socket.setdefaulttimeout(None)


def test_timeout_individual():
    def handler(request):
        time.sleep(0.5)
        return tests.http_response_bytes()

    http = httplib2.Http(timeout=0.1)
    http.force_exception_to_status_code = True

    with tests.server_request(handler) as uri:
        response, content = http.request(uri)
        assert response.status == 408
        assert response.reason.startswith("Request Timeout")


def test_timeout_https():
    c = httplib2.HTTPSConnectionWithTimeout('localhost', 80, timeout=47)
    assert 47 == c.timeout
