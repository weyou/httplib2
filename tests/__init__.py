import six
import socket
import sys
import threading
import time
from six.moves import http_client
import contextlib


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


def server_const_bytes(response_content, **kwargs):
    def handler(sock):
        sock.recv(8 << 10)
        sock.sendall(response_content)

    return server_socket(handler, **kwargs)


def server_const_http(proto='HTTP/1.0', status='200 OK', headers=None, body='', add_content_length=False, **kwargs):
    if headers is None:
        headers = {}
    if add_content_length:
        headers['content-length'] = str(len(body))
    header_string = ''.join('{0}: {1}\r\n'.format(k, v) for k, v in headers.items())
    response = '{proto} {status}\r\n{headers}\r\n{body}'.format(
        proto=proto,
        status=status,
        headers=header_string,
        body=body,
    ).encode()
    return server_const_bytes(response, **kwargs)


def server_reflect(**kwargs):
    def handler(sock):
        data = sock.recv(8 << 10)
        line = data.decode().splitlines()[0]
        method, uri, proto = line.split()
        headers = {
            'request-method': method,
        }
        header_string = ''.join('{0}: {1}\r\n'.format(k, v) for k, v in headers.items())
        body = '''\
uri={1}\n\
protocol={2}\n\
'''.format(method, uri, proto)
        response = '''HTTP/1.0 200 OK\r\n{0}\r\n{1}'''.format(header_string, body).encode()
        sock.sendall(response)

    return server_socket(handler, **kwargs)
