import sys
from application_layer import download

# ensure another argument given (for URL)
if len(sys.argv) < 2:
    sys.exit('The URL representing the html to download must be specified.')
url = sys.argv[1]

# download http response (html)
download(url)