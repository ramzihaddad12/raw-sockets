import re, constants
from urllib.parse import urlparse
from transport_layer import TransportSocket

# Write http response to a file
# URL is given to determine file name
def download(url):
    sock = socket_connect(urlparse(url).hostname)
    resp = send_get_request(sock, url)
    sock.close()

    file = open(get_filename(url), 'wb')
    headers_end = resp.rfind(b'\r\n')
    if headers_end == len(resp) - 2:
        headers_end = resp.rfind(b'\r\n', 0, headers_end)
    file.write(resp[headers_end:])
    file.close()


# Create custom TCP socket and connect
def socket_connect(host, port=80):
    sock = TransportSocket()
    sock.connect((host, port))
    return sock


# Send a get request, return the response
def send_get_request(sock, url):
    sock.send_data(build_http_get_request(url))
    resp = sock.receive_all()
    return resp


# Build an encoded HTTP GET request for the given URL
def build_http_get_request(url):
    parsed = urlparse(url)
    uri = parsed.path if parsed.path else '/'
    get_request = f"""\
GET {uri} HTTP/1.1{constants.CR}
Host: {parsed.hostname}{constants.END}"""

    return get_request.encode('utf-8')


# Find status for the given response
def get_http_status(resp):
    status_pattern = re.compile(r'HTTP/1.1 ([0-9]{3})')
    try:
        return int(status_pattern.findall(resp)[0])
    except IndexError:
        return 500

# Get filename based on url
# if url doesn't include a path, return index.html
def get_filename(url):
    uri = urlparse(url).path
    if uri and uri[-1] != '/':
        return url.split('/')[-1]
    else:
        return 'index.html'
