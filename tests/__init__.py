import contextlib
import email.utils
import hashlib
import os
import shutil
import six
import socket
import sys
import threading
from six.moves import http_client


if sys.version_info < (3,):
    BufferBase = six.StringIO
else:
    import io
    BufferBase = io.BytesIO


@contextlib.contextmanager
def assert_raises(exc_type):
    try:
        yield
    except exc_type:
        pass
    else:
        name = str(exc_type)
        try:
            name = exc_type.__name__
        except AttributeError:
            pass
        assert False, 'Expected exception {0}'.format(name)


class Request(object):
    def __init__(self):
        self.headers = {}


def read_request(sock):
    buf = sock.recv(8 << 10)
    r = request_from_bytes(buf)
    r.client = sock
    return r


def request_from_bytes(buf):
    line, rest = buf.split(b'\r\n', 1)
    r = Request()
    r.method, r.uri, r.proto = line.decode().split(' ', 2)
    hs, r.body = rest.split(b'\r\n\r\n', 1)
    hsl = (line.decode().split(':', 1) for line in hs.split(b'\r\n'))
    r.headers = {t[0].lower(): t[1].lstrip() for t in hsl}
    return r


class MockResponse(BufferBase):
    def __init__(self, body, **kwargs):
        BufferBase.__init__(self, body)
        self.headers = kwargs

    def items(self):
        return self.headers.items()

    def iteritems(self):
        return six.iteritems(self.headers)


class MockHTTPConnection(object):
    '''This class is just a mock of httplib.HTTPConnection used for testing
    '''

    def __init__(self, host, port=None, key_file=None, cert_file=None,
                 strict=None, timeout=None, proxy_info=None):
        self.host = host
        self.port = port
        self.timeout = timeout
        self.log = ''
        self.sock = None

    def set_debuglevel(self, level):
        pass

    def connect(self):
        'Connect to a host on a given port.'
        pass

    def close(self):
        pass

    def request(self, method, request_uri, body, headers):
        pass

    def getresponse(self):
        return MockResponse(b'the body', status='200')


class MockHTTPBadStatusConnection(object):
    '''Mock of httplib.HTTPConnection that raises BadStatusLine.
    '''

    num_calls = 0

    def __init__(self, host, port=None, key_file=None, cert_file=None,
                 strict=None, timeout=None, proxy_info=None):
        self.host = host
        self.port = port
        self.timeout = timeout
        self.log = ''
        self.sock = None
        MockHTTPBadStatusConnection.num_calls = 0

    def set_debuglevel(self, level):
        pass

    def connect(self):
        pass

    def close(self):
        pass

    def request(self, method, request_uri, body, headers):
        pass

    def getresponse(self):
        MockHTTPBadStatusConnection.num_calls += 1
        raise http_client.BadStatusLine('')


@contextlib.contextmanager
def server_socket(fun, accept_count=1, timeout=5):
    def serve_loop(srv):
        for _ in six.moves.range(accept_count):
            client, _ = srv.accept()
            client.settimeout(timeout)
            fun(client)
            client.shutdown(socket.SHUT_WR)

    server = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    server.bind(('localhost', 0))
    try:
        server.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    except socket.error as ex:
        print('non critical error on SO_REUSEADDR', ex)
    server.listen(10)
    server.settimeout(timeout)
    t = threading.Thread(target=serve_loop, args=(server,))
    t.daemon = True
    t.start()
    yield u'http://{0}:{1}/'.format(*server.getsockname())
    server.close()
    t.join()


def server_request(request_handler, **kwargs):
    def socket_handler(sock):
        r = read_request(sock)
        response = request_handler(request=r)
        sock.sendall(response)

    return server_socket(socket_handler, **kwargs)


def server_const_bytes(response_content, **kwargs):
    def handler(sock):
        read_request(sock)
        sock.sendall(response_content)

    return server_socket(handler, **kwargs)


_http_kwargs = (
    'proto', 'status', 'headers', 'body', 'add_content_length', 'add_date', 'add_etag',
)


def http_response_bytes(proto='HTTP/1.0', status='200 OK', headers=None, body=b'',
                        add_content_length=False, add_date=False, add_etag=False,
                        **kwargs):
    if headers is None:
        headers = {}
    if add_content_length:
        headers['content-length'] = str(len(body))
    if add_date:
        headers['date'] = email.utils.formatdate()
    if add_etag:
        headers['etag'] = '"{0}"'.format(hashlib.md5(body).hexdigest())
    header_string = ''.join('{0}: {1}\r\n'.format(k, v) for k, v in headers.items())
    response = '{proto} {status}\r\n{headers}\r\n'.format(
        proto=proto,
        status=status,
        headers=header_string,
    ).encode() + body
    return response


def make_http_reflect(**kwargs):
    def fun(request):
        kw = kwargs.copy()
        request_headers = ''.join('header-{0}: {1}\n'.format(k, v) for k, v in six.iteritems(request.headers))
        response_headers = kw.setdefault('headers', {})
        response_headers['request-method'] = request.method
        body = '''\
uri={1}\n\
protocol={2}\n\
{3}\n\
'''.format(request.method, request.uri, request.proto, request_headers).encode()
        kw.setdefault('body', body)
        response = http_response_bytes(**kw)
        return response
    return fun


def server_route(routes, **kwargs):
    response_404 = http_response_bytes(status='404 Not Found')
    response_wildcard = routes.get('')

    def handler(sock):
        request = read_request(sock)
        target = routes.get(request.uri, response_wildcard) or response_404
        if callable(target):
            response = target(request=request)
        else:
            response = target
        sock.sendall(response)

    return server_socket(handler, **kwargs)


def server_const_http(**kwargs):
    response_kwargs = {
        k: kwargs.pop(k) for k in dict(kwargs)
        if k in _http_kwargs
    }
    response = http_response_bytes(**response_kwargs)
    return server_const_bytes(response, **kwargs)


def server_reflect(**kwargs):
    response_kwargs = {
        k: kwargs.pop(k) for k in dict(kwargs)
        if k in _http_kwargs
    }
    http_handler = make_http_reflect(**response_kwargs)
    return server_request(http_handler, **kwargs)


def get_cache_path():
    default = './_httplib2_test_cache'
    path = os.environ.get('httplib2_test_cache_path') or default
    if os.path.exists(path):
        shutil.rmtree(path)
    return path
