#!/usr/bin/env python3
from http.server import SimpleHTTPRequestHandler
import socketserver
import logging

def get_secret():
    secret_fpath = '/run/secrets/my_secret'
    try:
        with open(secret_fpath, 'r') as f:
            return f.read().strip()
    except FileNotFoundError:
        return 'not exists!!'

class MyHandler(SimpleHTTPRequestHandler):
    def do_GET(self):
        logging.info("GET request,\nPath: %s\nHeaders:\n%s\n", str(self.path), str(self.headers))
        self.send_response(200)
        self.send_header('Content-Type', 'text/html')
        self.end_headers()
        message = 'Secret: ' + get_secret()
        self.wfile.write(bytes(message, 'utf8'))

PORT = 8080

logging.basicConfig(level=logging.INFO, format='%(asctime)s - %(message)s')
with socketserver.TCPServer(("", PORT), MyHandler) as httpd:
    httpd.serve_forever()

