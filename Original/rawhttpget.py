import sys
import urllib.parse
import transport_layer
import _http

url = sys.argv[1]
host_name = urllib.parse.urlparse(url).hostname

#Construct our socket
s = transport_layer.TCPSocket()
#Connect to the remote host
s.connect((host_name, 80))

#Create request
request = _http.getRequestForURL(url)

#Send request to host
s.send(request)

#Get all data from the request
response = s.recvall()

#Save data to disk
_http.saveResponse(response, url)

#Close the socket
s.close()
