import httplib2
import pickle
import pytest
import sys
import tests


@pytest.mark.skipif(
    sys.version_info <= (3,),
    reason='TODO: httplib2._convert_byte_str was defined only in python3 code version',
)
def test_ConvertByteStr():
    with tests.assert_raises(TypeError):
        httplib2._convert_byte_str(4)
    assert httplib2._convert_byte_str(b'Hello') == 'Hello'
    assert httplib2._convert_byte_str('World') == 'World'


def test_Reflector():
    uri = urllib.parse.urljoin(base, "reflector/reflector.cgi")
    response, content = http.request(uri, "GET")
    d = reflector(content)
    assert 'HTTP_USER_AGENT' in d


def test_PickleHttp():
    http = httplib2.Http()
    pickled_http = pickle.dumps(http)
    new_http = pickle.loads(pickled_http)

    assert tuple(sorted(new_http.__dict__)) == tuple(sorted(http.__dict__))
    for key in new_http.__dict__:
        if key in ('certificates', 'credentials'):
            assert new_http.__dict__[key].credentials == http.__dict__[key].credentials
        elif key == 'cache':
            assert new_http.__dict__[key].cache == http.__dict__[key].cache
        else:
            assert new_http.__dict__[key] == http.__dict__[key]


def test_PickleHttpWithConnection():
    http.request('http://bitworking.org',
                      connection_type=_MyHTTPConnection)
    pickled_http = pickle.dumps(http)
    new_http = pickle.loads(pickled_http)

    assertEqual(list(http.connections.keys()),
                     ['http:bitworking.org'])
    assert new_http.connections == {}


def test_PickleCustomRequestHttp():
    def dummy_request(*args, **kwargs):
        return new_request(*args, **kwargs)
    dummy_request.dummy_attr = 'dummy_value'

    http.request = dummy_request
    pickled_http = pickle.dumps(http)
    assert b"S'request'" not in pickled_http
