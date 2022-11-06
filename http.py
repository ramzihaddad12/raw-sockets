import sys, re, constants, transport_layer
from urllib.parse import urlparse

# Write http response to a file
# URL is given to determine file name
def download(url):
    sock = socket_connect(urlparse(url).hostname)
    resp = get_request(sock, url)
    sock.close()

    if get_status_code(resp) == 200:
        file = open(get_filename(url), 'w')
        file.write(get_data(resp))
        file.close()
    else:
        sys.exit('Unable to retrieve HTML content for non-200 responses.')


# Create custom TCP socket and connect
def socket_connect(host, port=80):
    sock = transport_layer.TCPSocket()
    sock.connect(host, port)
    return sock


# Send a get request, return the response
def get_request(sock, url):
    sock.send(form_get_request(url))
    resp = sock.recvall()
    return resp


# Form an encoded GET request for the given URL
def form_get_request(url):
    parsed = urlparse(url)
    uri = parsed.path if parsed.path else '/'
    get_request = f"""\
GET {uri} HTTP/1.1{constants.CR}
Host: {parsed.hostname}{constants.END}"""

    return get_request.encode('utf-8')


# Find status code for the given response
def get_status_code(resp):
    status_code_pattern = re.compile(r'HTTP/1.1 ([0-9]{3})')
    try:
        return int(status_code_pattern.findall(resp)[0])
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


# Get response body from HTTP response
def get_data(resp):
    body_start = resp.find(constants.END) + 4
    return resp[body_start:]
