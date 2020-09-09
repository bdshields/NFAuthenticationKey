#!/usr/bin/python3

import sys
import signal
import base64
import json
import random
from datetime import datetime
from Crypto.Cipher import AES



def _pad(s):
    return s + (16 - len(s) % 16) * chr(16 - len(s) % 16)



def processData():
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
    for line in sys.stdin:
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
                    if date.timestamp() < datetime.now().timestamp():
                        print ("\n\nWARNING: Cookie data appears to have expired, log into Netflex and try again.")
                    value = date.timestamp()
            if key != "NA":
                cookie[key]=value
            state=1
    cookies.append(cookie)
    data['data']=dict()
    data['data']['cookies']=cookies
    return data


# generate random PIN
PIN=random.randrange(1000,9999,1)
key="{}{}{}{}".format(PIN,PIN,PIN,PIN)

iv=b'\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00'


print ("Paste cookie data here, press Ctrl-D twice when finished:")



data = processData()

# Generate json
json_data = json.dumps(data)

#print ("{}".format(json_data))

# initialise the cipher
cipher = AES.new(key, AES.MODE_CBC, iv)

# encrypt the data
encoded = cipher.encrypt(_pad(json_data))

# convert to base64
output_data = base64.standard_b64encode(encoded)

# print ("Output: {}".format(output_data))

# Write data to file
f = open("NFAuthentication.Key","w")
f.write(output_data.decode("utf-8"))
f.close()

print ("\n\nAuthentication file has been created. Your PIN is: {}".format(PIN))


