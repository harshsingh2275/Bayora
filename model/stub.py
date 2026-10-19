import http.server
import json
import os
import signal
import sys

SERVICE_NAME = os.getenv("SERVICE_NAME", "model")
PORT = int(os.getenv("SERVICE_PORT", "8080"))

class StubHandler(http.server.BaseHTTPRequestHandler):
    def do_GET(self):
        if self.path in ("/health",):
            self.send_response(200)
            self.send_header("Content-Type", "application/json")
            self.end_headers()
            payload = {"status": "ok", "service": SERVICE_NAME}
            self.wfile.write(json.dumps(payload).encode("utf-8"))
        else:
            self.send_response(404)
            self.end_headers()

    def log_message(self, format, *args):
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
