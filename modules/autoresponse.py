import socket
import struct
from uuid import getnode as get_mac
from . import linuxWireshark as lw
from . import packetMaker


def domain_to_dns_bytes(domain: str) -> bytes:
    parts = domain.split('.')
    result = b''
    for part in parts:
        result += struct.pack('!B', len(part))
        for ch in part:
            result += struct.pack('!B', ord(ch))

    return result + b'\x00'


def dns_maker(identification:int,answers: list):
    """creating dns response with given parameters. note that answer is list of tuples"""
    qr = 1  # because query is response
    opcode = 0  # standard query
    aa = 0  # answer is not authoritative
    tc = 0
    rd = 0
    ra = 0  # recursion is not available
    z = 0  # no use!
    rcode = 0   # no error
    flags = 0
    flags += (qr << 15) + (opcode << 11) + (aa << 10) + \
        (tc << 9) + (rd << 8) + (ra << 7) + (z << 4) + rcode
    No_answers = len(answers)

    dns_header = struct.pack('!HHHHHH',
                             identification,
                             flags,
                             0, # no question bcause this is answer!!
                             No_answers,
                             0, # no auth answers
                             0) # no additional information
    

    byte_ans = b''
    for ans in answers:
        if ans[1] == 'A':
            qtype = struct.pack('!H', 0x0001)
            qclass = struct.pack('!H',0x0001)
            ttl = struct.pack('!I',ans[2])
            rdlength = struct.pack('!H',ans[3])
            rdata = socket.inet_aton(ans[4])
            byte_ans += domain_to_dns_bytes(ans[0]) + qtype + qclass + ttl + rdlength + rdata

    return dns_header + byte_ans


def dns_response():
    answer = [] ################ you should answers you want

    conn = socket.socket(
            socket.AF_PACKET, socket.SOCK_RAW, socket.ntohs(3))
    s2 = socket.socket(socket.AF_INET, socket.SOCK_RAW, socket.IPPROTO_RAW)
    while True:
        raw_data, addr = conn.recvfrom(65535)
        dest_mac, src_mac, eth_proto, data = lw.data_link_unpack(raw_data)
        if eth_proto == 8 or eth_proto == 56710:
            network_header, data = lw.network_unpack(data)
            if network_header['upper_layer'] == 6:
                transport_header, data = lw.transport_unpack(data, 'TCP')
                prtcl = transport_header['service']
                if prtcl == 'dns':
                    dns_header = lw.app_unpack(data, 'dns')
                    dns_response = dns_maker(dns_header['identification'],answer)
                    src_ip = network_header['32_bit_destinationIP']
                    dst_ip = network_header['32_bit_sourceIP']
                    src_prt = transport_header['dst_port']
                    dst_prt = transport_header['src_port']
                    ip = packetMaker.ipv4_header_maker(src_ip,dst_ip,network_header['16_bit_identifier'])
                    tcp = packetMaker.tcp_header_maker(dst_prt,src_ip,dst_ip,payload=dns_response)
                    packet = ip + tcp + dns_response
                    s2.sendto(packet, (dst_ip, 0))
            
            if network_header['upper_layer'] == 17:
                transport_header, data = lw.transport_unpack(data, 'UDP')
                prtcl = transport_header['service']
                if prtcl == 'dns':
                    dns_header = lw.app_unpack(data, 'dns')
                    dns_response = dns_maker(dns_header['identification'],answer)
                    src_ip = network_header['32_bit_destinationIP']
                    dst_ip = network_header['32_bit_sourceIP']
                    src_prt = transport_header['dst_port']
                    dst_prt = transport_header['src_port']
                    ip = packetMaker.ipv4_header_maker(src_ip,dst_ip,network_header['16_bit_identifier'])
                    tcp = packetMaker.tcp_header_maker(dst_prt,src_ip,dst_ip,payload=dns_response)
                    packet = ip + tcp + dns_response
                    s2.sendto(packet, (dst_ip, 0))



# def icmp_unpack(data):
#     type, code, checksum = struct.unpack('! B B H', data[:4])
#     return type, code, hex(checksum), repr(data[4:])


def ARP_unpack1(data):
    hdr = struct.unpack
    hdr = struct.unpack("!HHBBH6s4s6s4s", data[:28])
    header = {
        'hardware_type': hdr[0],
        'protocol_type': hex(hdr[1]),
        'hardware_add_len': hdr[2],
        'protocol_add_len': hdr[3],
        'operation': hdr[4],
        'sender_MAC_add': hdr[5],
        'sender_IP_add': socket.inet_ntoa(hdr[6]),
        'target_MAC_add': hdr[7],
        'target_IP_add': socket.inet_ntoa(hdr[8])
    }
    return header, data[28:]



# awnser if i have des ip addr
def arp_reply_maker(data):
    # mishe ye tabe dige seda kard ke ok kone
    ARP_header, data = ARP_unpack1(data)
    hardware_type = ARP_header['hardware_type']
    protocol_type = int(ARP_header['protocol_type'], 16)  # ??
    hardware_add_len = ARP_header['hardware_add_len']
    protocol_add_len = ARP_header['protocol_add_len']
    operation = 2
    mymac = get_mac()
    sender_MAC_add = (mymac).to_bytes(6, byteorder='big')
    sender_IP_add = socket.inet_aton(ARP_header['target_IP_add'])
    target_MAC_add = ARP_header['sender_MAC_add']  # to int!
    target_IP_add = socket.inet_aton(ARP_header['sender_IP_add'])
    packet = struct.pack('!HHBBH6s4s6s4s',
                         hardware_type,
                         protocol_type,
                         hardware_add_len,
                         protocol_add_len,
                         operation,
                         sender_MAC_add,
                         sender_IP_add,
                         target_MAC_add,
                         target_IP_add
                         )
    return packet


def icmp_reply_maker(icmp_packet):
    typ, code, chksum, dat = lw.icmp_unpack(icmp_packet)
    check_sum = 0
    packet = b''
    # echo
    if typ == 8 and code == 0:
        Type = 0
        identifier, sequence_num = struct.unpack('!H H', dat[:4])
        payload = dat[4:]
        packet = struct.pack('! B B H H H', Type, code,
                             check_sum, identifier, sequence_num)
    # timestamp
    elif typ == 13 and code == 0:
        Type = 14
        identifier, sequence_num, time1, time2, time3 = struct.unpack(
            '!H H I I I', dat[:16])
        packet = struct.pack('! B B H H I I I', Type, code,
                             check_sum, identifier, sequence_num, time1, time2, time3)
    # information
    elif typ == 15 and code == 0:
        Type = 16
        identifier, sequence_num = struct.unpack('!H H', dat[:4])
        check_sum = 0
        packet = struct.pack('! B B H H H', Type, code,
                             check_sum, identifier, sequence_num)
    # address mask
    elif typ == 17 and code == 0:
        Type = 18
        identifier, sequence_num, addr_mask = struct.unpack('!H H I', dat[:4])
        check_sum = 0
        address_mask = socket.inet_aton("255.255.255.0")
        packet = struct.pack('! B B H H H I', Type, code,
                             check_sum, identifier, sequence_num, address_mask)
    

    # Domain Name
    elif typ == 37 and code == 0:
        Type = 38
        identifier, sequence_num = struct.unpack('!H H', dat[:4])
        check_sum = 0
        time_to_live = bin(1000)
        packet = struct.pack('! B B H H H I', Type, code,
                             check_sum, identifier, sequence_num, time_to_live)
    cksm = packetMaker.checksum(packet)
    cksm = struct.pack('!H', cksm)
    return packet[:2] + cksm + packet[4:]

def ethernet_header_maker(raw_data):
    src_mac,dest_mac,proto = struct.unpack('! 6s 6s H', raw_data[:14])
    ethernet =  struct.pack('! 6s 6s H',  dest_mac,src_mac,proto)
    return ethernet


message = """by this command, you can auto responsed to below queries:
sudo python(3) babyshark autoresponse [types]
types:
    dns
    arp
    icmp
you can have mutliple auto responsed activated like this
'sudo python(3) babyshark autoresponse dns arp icmp'
to stop autorespnse press ctrl^c
or run sudo python(3) babyshark autoresponse --help to see this again!"""



def main(argv):
    if '--help' in argv:
        print(message)
    elif not (('dns' in argv) or ('icmp' in argv) or ('arp' in argv)):
        print("no type defiend. please run 'python(3) babyshark autoresponse --help' to see help")
    else:
        try:
            dns_answers = [] ################ you should fill it with RR

            conn = socket.socket(
                    socket.AF_PACKET, socket.SOCK_RAW, socket.ntohs(3))
            s2 = socket.socket(socket.AF_INET, socket.SOCK_RAW, socket.IPPROTO_RAW)
            while True:
                raw_data, addr = conn.recvfrom(65535)
                dest_mac, src_mac, eth_proto, data = lw.data_link_unpack(raw_data)

                if (eth_proto == 1544):
                    ARP_header, dat = lw.ARP_unpack(data)

                    if int(ARP_header['operation']) == 1:
                        arp_packet = arp_reply_maker(data)
                        ethernet_header = ethernet_header_maker(raw_data)
                        packet = b''
                        packet = ethernet_header + arp_packet
                        sock_r = socket.socket(socket.AF_PACKET, socket.SOCK_RAW)
                        sock_r.sendto(packet,addr)
                        print("Address Resolution Protocol request: ")
                        for key, value in ARP_header.items():
                            print("\t", key, ' : ', value)
                        ARP_header, data = lw.ARP_unpack(arp_packet)
                        print("Address Resolution Protocol reply: ")
                        for key, value in ARP_header.items():
                            print("\t", key, ' : ', value)
                        #break
                        ## print something here

                if eth_proto == 8 or eth_proto == 56710:
                    network_header, data = lw.network_unpack(data)

                    if (network_header['upper_layer'] == 1 and 'icmp' in argv):
                        reply = icmp_reply_maker(network_header[-1])
                        ip = packetMaker.ipv4_header_maker(src_ip,dst_ip,network_header['16_bit_identifier'])
                        packet = ip +reply
                        dst_ip = network_header['32_bit_sourceIP']
                        s2.sendto(packet,(dst_ip,0))
                        tp, code, checksum, data = icmp_unpack(network_header[-1])
                        ## add some print Here

                    if network_header['upper_layer'] == 6:
                        transport_header, data = lw.transport_unpack(data, 'TCP')
                        prtcl = transport_header['service']
                        if prtcl == 'domain' and 'dns' in argv:
                            dns_header = lw.app_unpack(data, 'dns')
                            dns_response = dns_maker(dns_header['identification'],answer)
                            src_ip = network_header['32_bit_destinationIP']
                            dst_ip = network_header['32_bit_sourceIP']
                            src_prt = transport_header['dst_port']
                            dst_prt = transport_header['src_port']
                            ip = packetMaker.ipv4_header_maker(src_ip,dst_ip,network_header['16_bit_identifier'])
                            tcp = packetMaker.tcp_header_maker(dst_prt,src_ip,dst_ip,payload=dns_response)
                            packet = ip + tcp + dns_response
                            s2.sendto(packet, (dst_ip, 0))
                            print("query:")
                            print(lw.app_unpack(data,'dns'))
                            print('response:')
                            print(lw.app_unpack(dns_response,'dns'))
                    
                    if network_header['upper_layer'] == 17:
                        transport_header, data = lw.transport_unpack(data, 'UDP')
                        prtcl = transport_header['service']
                        if prtcl == 'domain' and 'dns' in argv:
                            dns_header = lw.app_unpack(data, 'dns')
                            dns_response = dns_maker(dns_header['identification'],answer)
                            src_ip = network_header['32_bit_destinationIP']
                            dst_ip = network_header['32_bit_sourceIP']
                            src_prt = transport_header['dst_port']
                            dst_prt = transport_header['src_port']
                            # ip = packetMaker.ipv4_header_maker(src_ip,dst_ip,network_header['16_bit_identifier'])
                            # tcp = packetMaker.tcp_header_maker(dst_prt,src_ip,dst_ip,payload=dns_response)
                            # packet = ip + tcp + dns_response
                            s3 = socket.socket(socket.AF_INET,socket.SOCK_DGRAM)
                            s3.sendto(dns_response, (dst_ip, dst_prt))
                            print("query:")
                            print(lw.app_unpack(data,'dns'))
                            print('response:')
                            print(lw.app_unpack(dns_response,'dns'))

        except KeyboardInterrupt:
            print('autoresponse stoped')
        except :
            print('something went wrong; check internet and try again.')

    

            
        

