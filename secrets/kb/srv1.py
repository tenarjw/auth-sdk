#!/usr/bin/env python3

import os
import http.server as SimpleHTTPServer
import socketserver as SocketServer
import logging

def get_secret():
  secret_fpath = '/secrets/password.txt'
  if os.path.exists(secret_fpath):
    s = open(secret_fpath).read().rstrip('\n')
    return s
  else:
    return 'not exists!!'

class MyHandler(SimpleHTTPServer.SimpleHTTPRequestHandler):

  def do_GET(self):
    logging.info("GET request,\nPath: %s\nHeaders:\n%s\n", str(self.path), str(self.headers))
    self.send_response(200)
    self.send_header('Content-Type', 'text/html')
    self.end_headers()
    message = 'Sekret: ' + get_secret()
    self.wfile.write(bytes(message, 'utf8'))
    return

PORT=8088

logging.basicConfig(level=logging.INFO)
with SocketServer.TCPServer(("", PORT), MyHandler) as httpd:
    httpd.serve_forever()
