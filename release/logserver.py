import BaseHTTPServer

class MyHandler(BaseHTTPServer.BaseHTTPRequestHandler):
    def do_GET(s):
        idx = s.path.find('?')
        if idx >= 0:
            msg = s.path[idx+1:]
            idz = msg.find(",")
            cid = 0
            if idz >= 0:
                cid = msg[:idz]
            open("log_"+str(cid)+".csv","ab").write(msg+"\n")
        s.send_response(200)
        s.end_headers()
HOST_NAME = 'PATCH ME'
PORT_NUMBER = 80
server_class = BaseHTTPServer.HTTPServer
print "Running!"
httpd = server_class((HOST_NAME, PORT_NUMBER), MyHandler)
try:
    httpd.serve_forever()
except KeyboardInterrupt:
    pass
httpd.server_close()