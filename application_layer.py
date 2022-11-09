import constants, re
from urllib.parse import urlparse
from transport_layer import TransportSocket

# Write http response to a file
# URL is given to determine file name
def download(url):
    # get resp from url with custom TCP socket
    sock = socket_connect(urlparse(url).hostname)
    raw_resp = send_get_request(sock, url)
    sock.close()

    # open file and write bytes
    file = open(get_filename(url), 'wb')
    file.write(filter_resp(raw_resp))
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


# Filter out headers + non-related html bytes
def filter_resp(raw_resp):
    headers_end = raw_resp.find(b'\r\n\r\n')
    resp = raw_resp[headers_end + 2:]
    resp = re.sub(rb'\r\n\r\n\w*\r\n|\r\n\w*\r\n\r\n|\r\n\w*\r\n', b'', resp).lstrip()
    return resp


# Get filename based on url
# if url doesn't include a path, return index.html
def get_filename(url):
    uri = urlparse(url).path
    if uri and uri[-1] != '/':
        return url.split('/')[-1]
    else:
        return 'index.html'
