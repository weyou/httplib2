import httplib2
import mock
import socket
import sys
import tests
from six.moves import http_client


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
