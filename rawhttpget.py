import sys, http

# ensure another argument given (for URL)
if len(sys.argv) < 2:
    sys.exit('The URL representing the html to download must be specified.')
url = sys.argv[1]

# download http response (html)
http.download(url)