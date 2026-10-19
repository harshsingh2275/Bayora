import http.server
import json
import os
import signal
import sys

SERVICE_NAME = os.getenv("SERVICE_NAME", "gateway")
PORT = int(os.getenv("SERVICE_PORT", "8000"))

class StubHandler(http.server.BaseHTTPRequestHandler):
    def do_GET(self):
        # SECURITY: Strip and do not log sensitive headers or query params
        if self.path in ("/health", "/api/health") or self.path.startswith("/api/"):
            self.send_response(200)
            self.send_header("Content-Type", "application/json")
            self.end_headers()
            payload = {"status": "ok", "service": SERVICE_NAME}
            self.wfile.write(json.dumps(payload).encode("utf-8"))
        else:
            self.send_response(404)
            self.end_headers()

    def do_POST(self):
        if self.path.startswith("/api/"):
            self.send_response(200)
            self.send_header("Content-Type", "application/json")
            self.end_headers()
            payload = {"status": "ok", "service": SERVICE_NAME}
            self.wfile.write(json.dumps(payload).encode("utf-8"))
        else:
            self.send_response(404)
            self.end_headers()

    def log_message(self, format, *args):
        # SECURITY: Suppress raw request logging to avoid leaking headers/tokens
        pass

def run():
    server = http.server.ThreadingHTTPServer(("0.0.0.0", PORT), StubHandler)
    def shutdown(signum, frame):
        sys.exit(0)
    signal.signal(signal.SIGTERM, shutdown)
    signal.signal(signal.SIGINT, shutdown)
    server.serve_forever()

if __name__ == "__main__":
    run()
