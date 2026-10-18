"""One startup probe; exact read-only HTTP routes. No upload or command API."""
import json
import os
import signal
import threading
from http.server import BaseHTTPRequestHandler, HTTPServer

from probe import reply, run_probe


class State:
    def __init__(self):
        self.lock = threading.Lock(); self.cancel = threading.Event()
        self.value = reply('PENDING','STARTUP_PROBE_PENDING')
    def run(self):
        try: value = run_probe(self.cancel)
        except Exception: value = reply('INCONCLUSIVE','PROBE_INTERNAL_ERROR')
        with self.lock: self.value = value
        print(json.dumps(value,sort_keys=True),flush=True)
    def snapshot(self):
        with self.lock: return self.value


def handler_for(state):
    class Handler(BaseHTTPRequestHandler):
        server_version = 'GenericCapabilityProbe'
        sys_version = ''
        timeout = 5
        def log_message(self, *_): pass  # Never log request paths, bodies, or headers.
        def respond(self, status, value):
            body = json.dumps(value,sort_keys=True).encode()
            self.send_response(status)
            self.send_header('Content-Type','application/json')
            self.send_header('Content-Length',str(len(body)))
            self.send_header('Cache-Control','no-store')
            self.send_header('X-Content-Type-Options','nosniff')
            self.send_header('Connection','close')
            self.end_headers(); self.close_connection = True
            if self.command != 'HEAD':
                try: self.wfile.write(body)
                except (BrokenPipeError, ConnectionResetError): pass
        def do_GET(self):
            if self.path == '/healthz': self.respond(200,{'status':'HEALTHY'} )
            elif self.path in ('/','/result'): self.respond(200,state.snapshot())
            else: self.respond(404,{'code':'NOT_FOUND'})
        do_HEAD = do_GET
        def reject(self): self.respond(405,{'code':'METHOD_NOT_ALLOWED'})
        do_POST = do_PUT = do_PATCH = do_DELETE = do_OPTIONS = do_TRACE = do_CONNECT = reject
    return Handler


def main():
    port = int(os.environ.get('PORT','10000'))
    if not 1024 <= port <= 65535: raise ValueError('INVALID_PORT')
    state = State(); server = HTTPServer(('0.0.0.0',port),handler_for(state))
    def stop(*_):
        state.cancel.set()
        threading.Thread(target=server.shutdown,daemon=True).start()
    signal.signal(signal.SIGTERM,stop); signal.signal(signal.SIGINT,stop)
    thread = threading.Thread(target=state.run,name='one-startup-probe',daemon=True)
    thread.start()
    try: server.serve_forever(poll_interval=.2)
    finally:
        state.cancel.set(); server.server_close(); thread.join(8)


if __name__ == '__main__': main()
