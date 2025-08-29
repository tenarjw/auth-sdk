#!/usr/bin/env python3
# coding: utf-8

from http.server import BaseHTTPRequestHandler, HTTPServer
from urllib.parse import parse_qs, urlparse

global acode
acode=[]

class LocalServer(BaseHTTPRequestHandler):
    global acode
#    acode=[]

    def __init__(self, *args):
        super(LocalServer, self).__init__(*args)

    # GET
    def do_GET(self):
        # Send response status code
        self.send_response(200)
        # Send headers
        self.send_header('Content-type', 'text/html')
        self.end_headers()
        try:
            qs = parse_qs(urlparse(self.path).query)
            code=qs["code"][0]
            acode.append(code)
        except Exception as e:
            print("Error! %s" % e)
        try:        
            self.server.stop = True
            message = "Authorization is success, you can close this page now."
        except Exception as e:
            message = "Error! %s" % e
        # Send message back to client
#        self.wfile.write(bytes(message, "utf8"))
        return


class StoppableHTTPServer(HTTPServer):
    """http server that reacts to self.stop flag"""

    def __init__(self, *args):
#        self.code=''
        super(StoppableHTTPServer, self).__init__(*args)
        self.stop = False

    def serve_forever(self):
        """Handle one request at a time until stopped."""
        self.stop = False
        while not self.stop:
            self.handle_request()


def runHTTPServer(ip,port):
    print('starting server...')
    server_address = (ip, port)
    httpd = StoppableHTTPServer(server_address, LocalServer)
    print('running server...')
    httpd.serve_forever()
    print('stop server')


