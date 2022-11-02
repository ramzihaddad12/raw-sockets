import sys

# ensure another argument given (for URL)
if len(sys.argv) < 2:
    sys.exit('The URL representing the html to download must be specified.')
url = sys.argv[1]

# create socket and connect
sock = tcp.TCPSocket()
host = urlparse(url).hostname
port = 80
sock.connect((host, port))

# save http to directory
http.download_response(http.get_request(sock, url))

# close socket
sock.close()