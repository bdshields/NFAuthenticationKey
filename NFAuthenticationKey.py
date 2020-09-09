#!/usr/bin/python

import base64
import json
import sys
from datetime import datetime
from Crypto.Cipher import AES


def _pad(s):
    return s + (16 - len(s) % 16) * chr(16 - len(s) % 16)


def processFile(filename):
    f = open(filename)
    data = {}
    cookies = []
    cookie = dict()
    data['app_name']="NFAuthenticationKey"
    data['app_version']="1.0.0.0"
    data['app_system']="Windows"
    data['app_author']="CastagnaIT"
    data['timestamp']=int(datetime.now().timestamp())+432000
    state=0
    key =""
    for line in f:
        line = line.rstrip()
        if line == "Name":
            if state != 0:
                cookies.append(cookie)
                cookie = dict()
            key="name"
            state=2
        elif state == 1:
            if line == "Content":
                key="value"
            elif line == "Domain":
                key="domain"
            elif line == "Path":
                key="path"
            elif line == "Accessible to script":
                key="httpOnly"
            elif line == "Send for":
                key="secure"
            elif line == "Expires":
                key="expires"
            else:
                key="NA"
            state = 2
        elif state == 2:
            value=line
            if key == "httpOnly":
                if value == "Yes":
                    value=False
                else:
                    value=True
            elif key=="secure":
                if value == "Secure same-site connections only":
                    value=True
                else:
                    value=False
            elif key=="expires":
                if value == "When the browsing session ends":
                    value = -1
                else:
                    # Tuesday, 8 September 2020 at 11:50:55
                    date = datetime.strptime(value, '%A, %d %B %Y at %H:%M:%S')
                    value = date.timestamp()
            if key != "NA":
                cookie[key]=value
            state=1
    data['data']=dict()
    data['data']['cookies']=cookies
    f.close()
    return data




key=b'1234123412341234'


iv=b'\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00'

infile=sys.argv[1]

data = processFile(infile)

json_data = json.dumps(data)

print ("{}".format(json_data))

cipher = AES.new(key, AES.MODE_CBC, iv)

encoded = cipher.encrypt(_pad(json_data))

output_data = base64.standard_b64encode(encoded)

print ("Output: {}".format(output_data))

f = open("NFAuthentication.Key","w")
f.write(output_data.decode("utf-8"))
f.close()


