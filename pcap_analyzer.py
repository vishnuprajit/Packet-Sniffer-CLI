import dpkt, socket, datetime, sys, re
import filter, attack_detect, validator

def mac_addr(address):
    """Convert a MAC address to a readable/printable string

       Args:
           address (str): a MAC address in hex form (e.g. '\x01\x02\x03\x04\x05\x06')
       Returns:
           str: Printable/readable MAC address
    """
    return ':'.join('%02x' % dpkt.compat_ord(b) for b in address)

def inet_to_str(inet):
    """Convert inet object to a string

        Args:
            inet (inet struct): inet network address
        Returns:
            str: Printable/readable IP address
    """
    # First try ipv4 and then ipv6
    try:
        return socket.inet_ntop(socket.AF_INET, inet)
    except ValueError:
        return socket.inet_ntop(socket.AF_INET6, inet)

def packetsData(pcap):
    packets = []
    for (timestamp, buf) in pcap:
        packet = {}
        
        print("Timestamp:", str(datetime.datetime.utcfromtimestamp(timestamp)))
        packet["Timestamp"] = str(datetime.datetime.utcfromtimestamp(timestamp))

        eth = dpkt.ethernet.Ethernet(buf)
        print("Ethernet Frame:", mac_addr(eth.src), "->", mac_addr(eth.dst), eth.type)
        packet["Source MAC"] = mac_addr(eth.src)
        packet["Destination MAC"] = mac_addr(eth.dst)

        if not isinstance(eth.data, dpkt.ip.IP):
            try:
                print("Non IP Packet not supported %s\n" % eth.data.__class__.name)
                continue
            except:
                continue

        ip = eth.data
        do_not_fragment = bool(ip.off & dpkt.ip.IP_DF)
        more_fragments = bool(ip.off & dpkt.ip.IP_MF)
        fragment_offset = ip.off & dpkt.ip.IP_OFFMASK

        print("IPv4: %s -> %s    (len=%d ttl=%d DF=%d MF=%d offset=%d)" % (inet_to_str(ip.src), inet_to_str(ip.dst), ip.len, ip.ttl, do_not_fragment, more_fragments, fragment_offset))
        packet["Packet"] = ""
        packet["Source IP"] = inet_to_str(ip.src)
        packet["Destination IP"] = inet_to_str(ip.dst)
        packet["Length"] = ip.len
        packet["TTL"] = ip.ttl
        packet["DF"] = do_not_fragment
        packet["MF"] = more_fragments
        packet["Offset"] = fragment_offset

        if isinstance(ip.data, dpkt.icmp.ICMP):
            icmp = ip.data
            
            print("Packet: ICMP\nICMP: type: %d code: %d checksum: %d data: %s" % (icmp.type, icmp.code, icmp.sum, repr(icmp.data)))
            packet["Packet"] = "ICMP"
            packet["ICMP"] = icmp.type
            packet["ICMP code"] = icmp.code
            packet["Checksum"] = icmp.sum
            packet["ICMP Data"] = repr(icmp.data) 

        elif isinstance(ip.data, dpkt.tcp.TCP):
            tcp = ip.data
            
            print("Packet: TCP\nTCP Port: %s -> %s Seq: %s Ack: %s\nFlags: %s Window: %s Checksum: %s Urgent Pointer: %s" % (tcp.sport, tcp.dport, tcp.seq, tcp.ack, tcp.flags, tcp.win, tcp.sum, tcp.urp))
            packet["Packet"] = "TCP"
            packet["Source Port"] = tcp.sport
            packet["Destination Port"] = tcp.dport
            packet["SEQ"] = tcp.seq
            packet["ACK"] = tcp.ack
            packet["Flags"] = tcp.flags
            packet["Window"] = tcp.win
            packet["Checksum"] = tcp.sum
            packet["URP"] = tcp.urp

            # Show if the TCP packet has SYN flag enabled
            if (tcp.flags & dpkt.tcp.TH_SYN):
                packet["SYN flag"] = True
            else:
                packet["SYN flag"] = False
            if (tcp.flags & dpkt.tcp.TH_ACK):
                packet["ACK flag"] = True
            else:
                packet["ACK flag"] = False
            if (tcp.flags & dpkt.tcp.TH_FIN):
                packet["FIN flag"] = True
            else:
                packet["FIN flag"] = False
            
            try:
                request = dpkt.http.Request(tcp.data)
                print("HTTP Request: %s" % repr(request))
            except(dpkt.dpkt.NeedData, dpkt.dpkt.UnpackError):
                pass
                 
        
        elif isinstance(ip.data, dpkt.udp.UDP):
            udp = ip.data

            packet["Packet"] = "UDP"
            packet["Source Port"] = udp.sport
            packet["Destination Port"] = udp.dport
            packet["Length"] = udp.ulen
            packet["Checksum"] = udp.sum

            print("Packet: UDP\nUDP Port: %s -> %s\nChecksum: %s Length: %s" % (udp.sport, udp.dport, udp.sum, udp.ulen))

        print()
        # print(packet)

        packets.append(packet)
    return packets

def filtering(packets):
    print("""\nWhat do you want to filter? (Input the choice number)
    1. IP address
    2. MAC address
    3. Port number
    4. Packet Type
    """)
    choice = int(input("What do you want to filter? Choice number: "))
    
    match choice:
        case 1:
            ip = input("Enter the IP address: ")
            if validator.ip_validator(ip):
                    result = filter.ipaddr(ip, packets)

        case 2:
            mac = input("Enter the MAC address: ")
            if validator.mac_validator(mac):
                result = filter.macaddr(mac, packets)

        case 3:
            port = int(input("Enter the Port number: "))
            result = filter.portno(port, packets)
            if port not in range(65536):
                flag = False
                print("Invalid Port number entered !!!")
                sys.exit()

        case 4:
            ptype = input("Enter the Packet type: ")
            result = filter.packet(ptype, packets)

        case default:
            return "Invalid Choice entered!"

    return result

def main():
    f = open(sys.argv[1], "rb")

    pcap = dpkt.pcap.Reader(f)
    packets = packetsData(pcap)

    print("Welcome to my Packet Sniffer tool !!!")

    print("""What do you want to do? (Input the choice number)
    1. Filter packets based on header values
    2. Scan Attack Detection
    3. Scan DoS Attack Detection
    4. Application layer Attack Detection
    """)
    choice = int(input("Enter your choice: "))

    match choice:
        case 1:
            result = filtering(packets)
            print(result)
        case 2:
            attack_detect.scan_attack_detection(packets)
        case 3:
            attack_detect.dos_attack_detection(packets)
        case 4:
            attack_detect.app_attack_detection(packets)


if __name__ == "__main__":
    main()