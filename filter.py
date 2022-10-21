def ipaddr(ip, packets): # Completed
    details = ""
    for packet in packets:
        if packet["Source IP"] == ip or packet["Destination IP"] == ip:
            for i, j in packet.items():
                details += i + ": " + str(j) + "\n"
            details += "\n"
    return details

def macaddr(mac, packets): # Completed
    details = ""
    for packet in packets:
        if packet["Source MAC"] == mac or packet["Destination MAC"] == mac:
            for i, j in packet.items():
                details += i + ": " + str(j) + "\n"
            details += "\n"
    return details

def portno(port, packets): # Completed
    details = ""
    for packet in packets:
        if packet["Packet"] == "TCP" or packet["Packet"] == "UDP":
            if packet["Source Port"] == int(port) or packet["Destination Port"] == int(port):
                for i, j in packet.items():
                    details += i + ": " + str(j) + "\n"
                details += "\n"
    return details

def packet(type, packets): # Completed
    details = ""
    for packet in packets:
        if packet["Packet"] == type:
            for i, j in packet.items():
                details += i + ": " + str(j) + "\n"
            details += "\n"
    return details