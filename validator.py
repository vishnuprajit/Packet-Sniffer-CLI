import re, sys

def ip_validator(ip):
    ip_format = re.compile(r'([1-9][0-9]?[0-9]?)\.([0-9]{1,3})\.([0-9]{1,3})\.([0-9]{1,3})')
    octets = ip.split(".")
    flag = True
    for octet in octets:
        if int(octet) not in range(256):
            flag = False 
    if flag and ip_format.findall(ip):
        return True
    print("Invalid IP format entered !!!")
    sys.exit()

def mac_validator(mac):
    mac_format = re.compile(r'([0-9a-f]{2}):([0-9a-f]{2}):([0-9a-f]{2}):([0-9a-f]{2}):([0-9a-f]{2}):([0-9a-f]{2})')
    if mac_format.findall(mac):
        return True
    print("Invalid MAC format entered !!!")
    sys.exit()
