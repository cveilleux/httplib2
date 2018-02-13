from __future__ import print_function
import base64
import binascii
import contextlib
import email.utils
import gzip
import hashlib
import httplib2
import os
import random
import shutil
import six
import socket
import threading
import traceback
import zlib
from six.moves import http_client, queue


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


class BufferedReader(object):
    '''io.BufferedReader with \r\n support
    '''
    def __init__(self, sock):
        self._buf = b''
        self._end = False
        self._newline = b'\r\n'
        self._sock = sock
        if isinstance(sock, bytes):
            self._sock = None
            self._buf = sock
            self._end = True

    def _fill(self, target=1, more=None, untilend=False):
        # crutch to enable request from bytes
        if self._sock is None:
            return
        if more:
            target = len(self._buf) + more
        while untilend or (len(self._buf) < target):
            chunk = self._sock.recv(8 << 10)
            # print('server.recv', chunk)
            if not chunk:
                self._end = True
                if untilend:
                    return
                else:
                    raise EOFError
            self._buf += chunk

    def peek(self, size):
        self._fill(target=size)
        return self._buf[:size]

    def read(self, size):
        self._fill(target=size)
        chunk, self._buf = self._buf[:size], self._buf[size:]
        return chunk

    def readall(self):
        self._fill(untilend=True)
        chunk, self._buf = self._buf, b''
        return chunk

    def readline(self):
        while True:
            i = self._buf.find(self._newline)
            if i >= 0:
                break
            self._fill(more=1)
        inext = i + len(self._newline)
        line, self._buf = self._buf[:inext], self._buf[inext:]
        return line


class Request(object):
    def __init__(self):
        self.headers = {}

    def __repr__(self):
        return 'Request ' + repr(vars(self))

    @staticmethod
    def from_bytes(bs):
        buf = BufferedReader(bs)
        return Request.from_buffered(buf)

    @staticmethod
    def from_buffered(buf):
        if buf._end:
            return None
        try:
            start_line = buf.readline()
        except EOFError:
            return None
        r = Request()
        r.raw = start_line
        r.method, r.uri, r.proto = start_line.rstrip().decode().split(' ', 2)
        assert r.proto.startswith('HTTP/')
        r.version = r.proto[5:]

        while True:
            line = buf.readline()
            r.raw += line
            line = line.rstrip()
            if not line:
                break
            t = line.decode().split(':', 1)
            r.headers[t[0].lower()] = t[1].lstrip()

        content_length_string = r.headers.get('content-length', '')
        if content_length_string.isdigit():
            content_length = int(content_length_string)
            r.body = r.body_raw = buf.read(content_length)
        elif r.headers.get('transfer-encoding') == 'chunked':
            raise NotImplemented
        elif r.version == '1.0':
            r.body = r.body_raw = buf.readall()
        else:
            r.body = r.body_raw = b''

        r.raw += r.body_raw
        return r


class MockResponse(six.BytesIO):
    def __init__(self, body, **kwargs):
        six.BytesIO.__init__(self, body)
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
def server_socket(fun, request_count=1, timeout=5):
    gresult = [None]
    gcounter = [0]

    def tick():
        gcounter[0] += 1
        return gcounter[0] < request_count

    def server_socket_thread(srv):
        try:
            while gcounter[0] < request_count:
                client, _ = srv.accept()
                try:
                    client.settimeout(timeout)
                    fun(client, tick)
                finally:
                    client.close()
            if gcounter[0] > request_count:
                gresult[0] = Exception('Request count expected={0} actual={1}'.format(request_count, gcounter[0]))
        except Exception as e:
            traceback.print_exc()
            gresult[0] = e

    server = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    server.bind(('localhost', 0))
    try:
        server.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    except socket.error as ex:
        print('non critical error on SO_REUSEADDR', ex)
    server.listen(10)
    server.settimeout(timeout)
    t = threading.Thread(target=server_socket_thread, args=(server,))
    t.daemon = True
    t.start()
    yield u'http://{0}:{1}/'.format(*server.getsockname())
    server.close()
    t.join()
    if gresult[0] is not None:
        raise gresult[0]


def server_yield(fun, **kwargs):
    rq = queue.Queue(1)
    rg = fun(rq.get)

    def server_yield_socket_handler(sock, tick):
        buf = BufferedReader(sock)
        while True:
            request = Request.from_buffered(buf)
            if request is None:
                break
            rq.put(request)
            response = six.next(rg)
            sock.sendall(response)
            if not tick():
                break

    return server_socket(server_yield_socket_handler, **kwargs)


def server_request(request_handler, **kwargs):
    def server_request_socket_handler(sock, tick):
        buf = BufferedReader(sock)
        while True:
            request = Request.from_buffered(buf)
            if request is None:
                break
            response = request_handler(request=request)
            sock.sendall(response)
            if not tick():
                break

    return server_socket(server_request_socket_handler, **kwargs)


def server_const_bytes(response_content, **kwargs):
    return server_request(lambda request: response_content, **kwargs)


_http_kwargs = (
    'proto', 'status', 'headers', 'body', 'add_content_length', 'add_date', 'add_etag', 'undefined_body_length',
)


def http_response_bytes(proto='HTTP/1.1', status='200 OK', headers=None, body=b'',
                        add_content_length=True, add_date=False, add_etag=False,
                        undefined_body_length=False,
                        **kwargs):
    if undefined_body_length:
        add_content_length = False
    if headers is None:
        headers = {}
    if add_content_length:
        headers['content-length'] = str(len(body))
    if add_date:
        headers['date'] = email.utils.formatdate()
    if add_etag:
        headers['etag'] = '"{0}"'.format(hashlib.md5(body).hexdigest())
    header_string = ''.join('{0}: {1}\r\n'.format(k, v) for k, v in headers.items())
    if not undefined_body_length and proto != 'HTTP/1.0' and 'content-length' not in headers:
        raise Exception('httplib2.tests.http_response_bytes: client could not figure response body length')
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
        # TODO: use request.raw instead of request_headers
        body = '''\
method={0}\n\
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

    def handler(request):
        target = routes.get(request.uri, response_wildcard) or response_404
        if callable(target):
            response = target(request=request)
        else:
            response = target
        return response

    return server_request(handler, **kwargs)


def server_const_http(**kwargs):
    response_kwargs = {
        k: kwargs.pop(k) for k in dict(kwargs)
        if k in _http_kwargs
    }
    response = http_response_bytes(**response_kwargs)
    return server_const_bytes(response, **kwargs)


def server_list_http(responses, **kwargs):
    i = iter(responses)

    def handler(request):
        return next(i)

    kwargs.setdefault('request_count', len(responses))
    return server_request(handler, **kwargs)


def server_reflect(**kwargs):
    response_kwargs = {
        k: kwargs.pop(k) for k in dict(kwargs)
        if k in _http_kwargs
    }
    http_handler = make_http_reflect(**response_kwargs)
    return server_request(http_handler, **kwargs)


def http_parse_auth(s):
    '''https://tools.ietf.org/html/rfc7235#section-2.1
    '''
    scheme, rest = s.split(' ', 1)
    result = {}
    while True:
        m = httplib2.WWW_AUTH_RELAXED.search(rest)
        if not m:
            break
        if len(m.groups()) == 3:
            key, value, rest = m.groups()
            result[key.lower()] = httplib2.UNQUOTE_PAIRS.sub(r'\1', value)
    return result


def http_reflect_with_auth(allow_scheme, allow_credentials, deny_response=None):
    '''
    allow_scheme - 'basic', 'digest', etc
    allow_credentials - sequence of ('name', 'password')
    '''
    nonce = gen_digest_nonce()
    opaque = gen_digest_nonce()
    realm = 'httplib2 test'

    def deny(**kwargs):
        if deny_response is not None:
            return deny_response

        if allow_scheme == 'basic':
            authenticate = 'basic realm="{realm}"'.format(realm=realm)
        elif allow_scheme == 'digest':
            authenticate = ', '.join((
                'digest realm="{realm}", qop="auth"',
                'nonce="{nonce}", opaque="{opaque}"'
            )).format(realm=realm, nonce=nonce, opaque=opaque)
        else:
            raise Exception('unknown allow_scheme={0}'.format(allow_scheme))
        deny_headers = {'www-authenticate': authenticate}
        kwargs.setdefault('status', 401)
        # supplied headers may overwrite generated ones
        deny_headers.update(kwargs.get('headers', {}))
        kwargs['headers'] = deny_headers
        kwargs.setdefault('body', b'HTTP authorization required')
        return http_response_bytes(**kwargs)

    def http_reflect_with_auth_handler(request):
        auth_header = request.headers.get('authorization', '')
        if not auth_header:
            return deny()
        if ' ' not in auth_header:
            return http_response_bytes(status=400, body=b'authorization header syntax error')
        scheme, data = auth_header.split(' ', 1)
        scheme = scheme.lower()
        if scheme != allow_scheme:
            return deny(body=b'must use different auth scheme')
        if scheme == 'basic':
            decoded = base64.b64decode(data).decode()
            username, password = decoded.split(':', 1)
            if (username, password) in allow_credentials:
                return make_http_reflect()(request)
            else:
                return deny(body=b'supplied credentials are not allowed')
        elif scheme == 'digest':
            for allow_username, allow_password in allow_credentials:
                digest = http_parse_auth(data)
                hasher = hashlib.md5
                ha1 = hasher(':'.join((allow_username, realm, allow_password)).encode()).hexdigest()
                ha2 = hasher(':'.join((request.method, request.uri)).encode()).hexdigest()
                allow_response = hasher(':'.join((
                    ha1,
                    digest.get('nonce', ''),
                    digest.get('nc', ''),
                    digest.get('cnonce', ''),
                    digest.get('qop', ''),
                    ha2,
                )).encode()).hexdigest()
                if digest.get('response', '') == allow_response:
                    return make_http_reflect()(request)
            return deny(body=b'supplied credentials are not allowed')
        else:
            return http_response_bytes(status=400, body=b'unknown authorization scheme={0}'.format(scheme))

    return http_reflect_with_auth_handler


def get_cache_path():
    default = './_httplib2_test_cache'
    path = os.environ.get('httplib2_test_cache_path') or default
    if os.path.exists(path):
        shutil.rmtree(path)
    return path


def gen_digest_nonce():
    d = b''.join(six.int2byte(random.randint(0, 255)) for _ in range(17))
    return binascii.hexlify(d)


def gen_password():
    length = random.randint(8, 64)
    return ''.join(six.unichr(random.randint(0, 127)) for _ in range(length))


def gzip_compress(bs):
    # gzipobj = zlib.compressobj(9, zlib.DEFLATED, zlib.MAX_WBITS | 16)
    # result = gzipobj.compress(text) + gzipobj.flush()
    buf = six.BytesIO()
    gf = gzip.GzipFile(fileobj=buf, mode='wb', compresslevel=6)
    gf.write(bs)
    gf.close()
    return buf.getvalue()


def gzip_decompress(bs):
    return zlib.decompress(bs, zlib.MAX_WBITS | 16)


def deflate_compress(bs):
    do = zlib.compressobj(9, zlib.DEFLATED, -zlib.MAX_WBITS)
    return do.compress(bs) + do.flush()


def deflate_decompress(bs):
    return zlib.decompress(bs, -zlib.MAX_WBITS)
