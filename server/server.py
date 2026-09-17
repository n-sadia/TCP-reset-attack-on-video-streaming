import http.server
import socketserver
import time

RATE = 100 * 1024   # 100 KB/s — slow enough that buffer stays small

class RateLimitedHandler(http.server.SimpleHTTPRequestHandler):
    def copyfile(self, source, outputfile):
        chunk = 4096S
        while True:
            buf = source.read(chunk)
            if not buf:
                break
            outputfile.write(buf)
            outputfile.flush()
            time.sleep(chunk / RATE)

with socketserver.TCPServer(("", 8000), RateLimitedHandler) as httpd:
    print("Serving at port 8000 (rate limited to 50KB/s)")
    httpd.serve_forever()