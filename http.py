import sys, re
from urllib.parse import urlparse

# Send a get request, return the response
def get_request(sock, url):
    sock.send(form_get_request(url))
    resp = sock.recv_all()
    return resp

# Form an encoded GET request for the given URL
def form_get_request(url):
    parsed = urlparse(url)
    uri = parsed.path if parsed.path else '/'
    get_request = f"""\
GET {uri} HTTP/1.1\r
Host: {parsed.hostname}\r\n\r\n"""

    return str.encode(get_request)

# Write http response to a file
# URL is given to determine file name
def download_response(url, resp):
    if status_code(resp) == 200:
        file = open()
        file.write()
        file.close()
    else:
        sys.exit('Unable to retrieve HTML content for non-200 responses.')

# Find status code for the given response
def status_code(resp):
    status_code_pattern = re.compile(r'HTTP/1.1 ([0-9]{3})')
    try:
        return int(status_code_pattern.findall(resp)[0])
    except IndexError:
        return 500

# get filename based on url
# if url doesn't include a path, return index.html
def filename(url):
    uri = urlparse(url).path
    if uri and uri[-1] != '/':
        return url.split('/')[-1]
    else:
        return 'index.html'
