#!/usr/bin/python3
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer

class Redirect(BaseHTTPRequestHandler):
    def do_GET(self):
        self.send_response(302)
        self.send_header('Location', 'https://192.168.5.1/portal')
        self.send_header('Content-Length', '0')
        self.end_headers()
    do_HEAD = do_GET

ThreadingHTTPServer(('192.168.5.1', 80), Redirect).serve_forever()
