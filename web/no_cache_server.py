from http.server import SimpleHTTPRequestHandler, HTTPServer

class NoCacheHTTPRequestHandler(SimpleHTTPRequestHandler):
    def end_headers(self):
        # 添加禁止缓存的 HTTP 头
        self.send_header('Cache-Control', 'no-store, no-cache, must-revalidate, max-age=0')
        self.send_header('Pragma', 'no-cache')
        self.send_header('Expires', '0')
        super().end_headers()

if __name__ == '__main__':
    server_address = ('', 8000)  # 监听所有地址，端口 8000
    httpd = HTTPServer(server_address, NoCacheHTTPRequestHandler)
    print("启动无缓存服务器，端口 8000...")
    httpd.serve_forever()