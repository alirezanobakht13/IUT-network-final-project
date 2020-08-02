import struct
import socket
from . import packetMaker
import textwrap
import time
import os
import datetime


def get_mac_addr(bytes_addr):
    bytes_str = map('{:02x}'.format, bytes_addr)
    mac_addr = ':'.join(bytes_str).upper()
    return mac_addr


def data_link_unpack(data):
    dest_mac, src_mac, proto = struct.unpack('! 6s 6s H', data[:14])
    return get_mac_addr(dest_mac), get_mac_addr(src_mac), socket.htons(proto), data[14:]


def ARP_unpack(data):
    hdr = struct.unpack
    hdr = struct.unpack("!HHBBH6s4s6s4s", data[:28])
    header = {
        'hardware_type': hdr[0],
        'protocol_type': hex(hdr[1]),
        'hardware_add_len': hdr[2],
        'protocol_add_len': hdr[3],
        'operation': hdr[4],
        'sender_MAC_add': get_mac_addr(hdr[5]),
        'sender_IP_add': socket.inet_ntoa(hdr[6]),
        'target_MAC_add': get_mac_addr(hdr[7]),
        'target_IP_add': socket.inet_ntoa(hdr[8])
    }
    return header, data[28:]


def network_unpack(data):
    ver = data[0] >> 4
    maindata = data
    if (ver == 4):
        hdr = struct.unpack
        hdr = struct.unpack('!BBHHHBBH4s4s', data[:20])
        header = {
            'versoin': "IPv4",
            'header_len': (hdr[0] & 0xF) * 4,  # ??*4
            'TOS': hdr[1],
            'lenght': hdr[2],
            '16_bit_identifier': hdr[3],
            'flags': hdr[4] >> 13,
            'fragment_offset': hdr[4] & 0x1FFF,
            'TTL': hdr[5],
            'upper_layer': hdr[6],
            'header_checksum':  hex(hdr[7]),
            '32_bit_sourceIP': socket.inet_ntoa(hdr[8]),
            '32_bit_destinationIP': socket.inet_ntoa(hdr[9])
        }
        return header, maindata[header['header_len']:]
    elif (ver == 6):
        hdr = struct.unpack
        hdr = struct.unpack('!IHBB16s16s', data[:40])
        header = {
            'versoin': "IPv6",
            'pri': (hdr[0] >> 20) & 0xFF,
            'flow_table': hdr[0] & 0xFFFFF,
            'payload_len': hdr[1],
            'upper_layer': hdr[2],
            'hop_limit': hdr[3],
            '128_bit_sourceIP': socket.inet_ntoa(hdr[4]),
            '128_bit_destinationIP': socket.inet_ntoa(hdr[5])
        }
        return header, data[40:]


def icmp_unpack(data):
    type, code, checksum = unpack('! B B H', data[:4])
    return type, code, hex(checksum), repr(data[4:])


def transport_unpack(data, version):
    payload = None
    header = {}
    if version.upper() == "UDP":
        payload = data[8:]
        hdr = struct.unpack('!HHHH', data[:8])
        header = {
            'protocol': 'UDP',
            'src_port': hdr[0],
            'dst_port': hdr[1],
            'length': hdr[2],
            'checksum': hdr[3]
        }
        header['service'] = packetMaker.services.get(
            str(header['dst_port']), None)
        return header, payload
    elif version.upper() == 'TCP':
        hdr = struct.unpack('!HHIIBBHHH', data[:20])
        header = {
            'protocol': 'TCP',
            'src_port': hdr[0],
            'dst_port': hdr[1],
            'seq_number': hdr[2],
            'ack_number': hdr[3],
            # it should multiply to 4 to be in byte
            'data_offset': hdr[4] >> 4,
            'NS': hdr[4] & 0x1,
            'CWR': hdr[5] >> 7,
            'ECE': (hdr[5] >> 6) & 0x1,
            'URG': (hdr[5] >> 5) & 0x1,
            'ACK': (hdr[5] >> 4) & 0x1,
            'PSH': (hdr[5] >> 3) & 0x1,
            'RST': (hdr[5] >> 2) & 0x1,
            'SYN': (hdr[5] >> 1) & 0x1,
            'FIN': hdr[5] & 0x1,
            'window_size': hdr[6],
            'checksum': hdr[7],
            'urg_ptr': hdr[8],
            'options': data[160:(32*(hdr[4] >> 4))]
        }
        header['service'] = packetMaker.services.get(
            str(header['dst_port']), None)
        payload = data[(4*header['data_offset']):]
        return header, payload


# ------------extract name in dns query -------------
def extract_name(data, ptr):
    domain = ""
    while True:
        count = struct.unpack('!B', data[ptr:ptr+1])
        count = count[0]
        if count == 0:
            ptr += 1
            return ptr, domain[:len(domain)-1]

        if (count >> 6) == 3:
            offset = struct.unpack('!H', data[ptr:ptr+2])
            offset = offset[0]
            offset = offset & 0x3FFF
            temp_ptr, temp_domain = extract_name(data, offset)
            domain += temp_domain
            ptr += 2
            return ptr, domain[:len(domain)]

        ptr += 1
        for i in range(count):
            temp_char = struct.unpack('!B', data[ptr:ptr+1])
            temp_char = temp_char[0]
            domain += str(chr(temp_char))
            ptr += 1
        domain += "."


def DNS(data):
    raw_header = struct.unpack('!HHHHHH', data[:12])
    identification = raw_header[0]
    flags = raw_header[1]
    No_questions = raw_header[2]
    No_answers = raw_header[3]
    No_auths = raw_header[4]
    No_additional = raw_header[5]

    ptr = 12

    # ----------- extracting questions ------------
    questions = []
    for _ in range(No_questions):
        ptr, domain = extract_name(data, ptr)
        qtype = struct.unpack('!H', data[ptr:ptr+2])
        qtype = qtype[0]
        ptr += 2
        qtype_name = ''

        # defining query type:
        if qtype == 0x0001:
            qtype_name = 'A'
        elif qtype == 0x0002:
            qtype_name = 'NS'
        elif qtype == 0x000f:
            qtype_name = 'MX'
        elif qtype == 0x0005:
            qtype_name = 'CNAME'
        else:
            qtype_name = str(qtype)

        qclass = struct.unpack('!H', data[ptr:ptr+2])
        qclass = qclass[0]
        ptr += 2
        qclass_name = ''
        if qclass == 0x0001:
            qclass_name = "INTERNET"
        else:
            qclass_name = str(qclass)

        questions.append((domain, qtype_name, qclass_name))

    answers = []
    for _ in range(No_answers):
        ptr, name = extract_name(data, ptr)
        # response type:
        qtype = struct.unpack('!H', data[ptr:ptr+2])
        qtype = qtype[0]
        ptr += 2
        qtype_name = ''
        if qtype == 0x0001:
            qtype_name = 'A'
        elif qtype == 0x0002:
            qtype_name = 'NS'
        elif qtype == 0x000f:
            qtype_name = 'MX'
        elif qtype == 0x0005:
            qtype_name = 'CNAME'
        else:
            qtype_name = str(qtype)

        # response class:
        qclass = struct.unpack('!H', data[ptr:ptr+2])
        qclass = qclass[0]
        ptr += 2
        qclass_name = ''
        if qclass == 0x0001:
            qclass_name = "INTERNET"
        else:
            qclass_name = str(qclass)

        # TTL
        ttl = struct.unpack('!I', data[ptr:ptr+4])
        ttl = ttl[0]
        ptr += 4

        # RDLENGTH
        rdlength = struct.unpack('!H', data[ptr:ptr+2])
        rdlength = rdlength[0]
        ptr += 2

        if qtype_name == 'NS' or qtype_name == 'MX' or qtype_name == 'CNAME':
            temp, rdata = extract_name(data, ptr)
        elif qtype_name == 'A':
            ip_addr = struct.unpack('!BBBB', data[ptr:ptr+4])
            rdata = f'{ip_addr[0]}.{ip_addr[1]}.{ip_addr[2]}.{ip_addr[3]}'
        else:
            rdata = data[ptr:ptr+rdlength]
        ptr += rdlength
        answers.append((name, qtype_name, qclass_name, ttl, rdlength, rdata))

    # TODO add auth and additional if needed

    unpacked = {
        'identification': identification,
        'QR': flags >> 15,
        'OPCODE': (flags >> 11) & 0xf,
        'AA': (flags >> 10) & 0x1,
        'TC': (flags >> 9) & 0x1,
        'RD': (flags >> 8) & 0x1,
        'RA': (flags >> 7) & 0x1,
        'Z': (flags >> 4) & 0x7,
        'RCODE': flags & 0xf,
        'question_count': No_questions,
        'answer_count': No_answers,
        'auth_count': No_auths,
        'additional_count': No_additional,
        'questions': questions,
        'answers': answers
    }

    return unpacked


def app_unpack(data, version):
    # TODO : check is decode type for http true of not
    if version == 'http':
        return data.decode('ascii')

    elif version == 'dns':
        return DNS(data)

    else:
        return data


def save_pcap(packets: list):
    max_size = 0
    for packet in packets:
        max_size = max(max_size, len(packet[1]))

    magic_number = 0xa1b2c3d4  # unsigned 32
    version_major = 2  # unsigned 16
    version_minor = 4  # unsigned 16
    thiszone = 0  # signed 32
    sigfigs = 0  # unsigned 32
    snaplen = max_size  # unsigned 32
    network = 1  # unsigned 32 ---REVIEW : maybe edit is needed

    global_header = struct.pack('!IHHiIII', magic_number, version_major,
                                version_minor, thiszone, sigfigs, snaplen, network)
    data = global_header
    for packet in packets:
        timestamp = packet[0]

        ts_sec, ts_usec = str(timestamp).split('.')
        ts_sec = int(ts_sec)
        ts_usec = int(ts_usec)
        incl_len = len(packet[1])
        orig_len = incl_len

        packet_header = struct.pack(
            '!IIII', ts_sec, ts_usec, incl_len, orig_len)

        data += packet_header
        data += packet[1]

    working_dir = os.getcwd()
    save_dir = os.path.join(working_dir, 'Pcaps')
    try:
        os.mkdir(save_dir)
    except:
        pass

    file_name = str(datetime.datetime.fromtimestamp(packets[0][0])).split('.')[
        0].replace(':', '-') + '.pcap'
    with open(os.path.join(save_dir, file_name), 'w+b') as f:
        f.write(data)
    return os.path.join(save_dir, file_name)


def show_summay(index, raw_data):
    dest_mac, src_mac, eth_proto, data = data_link_unpack(raw_data)
    if (eth_proto == 1544):  # if little endian 2054  0x0806
        ARP_header, data = ARP_unpack(data)
        print(f"#{index}", ARP_header['sender_IP_add'], "\t",
              ARP_header['sender_IP_add'], "\t", "ARP")
    elif (eth_proto == 8 or eth_proto == 56710):  # 2048
        network_header, data = network_unpack(data)
        if (network_header['upper_layer'] == 1):
            print(f"#{index}", network_header['32_bit_sourceIP'], "\t",
                  network_header['32_bit_destinationIP'], "\t", "ICMP")
        elif(network_header['upper_layer'] == 6):
            print(f"#{index}", network_header['32_bit_sourceIP'], "\t",
                  network_header['32_bit_destinationIP'], "\t", "TCP")
        elif(network_header['upper_layer'] == 17):
            print(f"#{index}", network_header['32_bit_sourceIP'], "\t",
                  network_header['32_bit_destinationIP'], "\t", "UDP")
    else:
        print(f"#{index}", dest_mac, "\t", src_mac, "\tother type")


def show_all(raw_data):
    # Ethernet
    dest_mac, src_mac, eth_proto, data = data_link_unpack(raw_data)
    print("Ethernet :\n\tDestination : ", dest_mac,
          "\n\tSource : ", src_mac, "\n\tType : ", eth_proto)
    # ARP
    if (eth_proto == 1544):  # if little endian 2054  0x0806
        ARP_header, data = ARP_unpack(data)
        print("Address Resolution Protocol : ")
        for key, value in ARP_header.items():
            print("\t", key, ' : ', value)
    # Network Layer
    elif (eth_proto == 8 or eth_proto == 56710):  # 2048
        network_header, data = network_unpack(data)
        print("Network Layer : ")
        for key, value in network_header.items():
            print("\t", key, ' : ', value)
        # ICMP
        if (network_header['upper_layer'] == 1):
            type, code, checksum, data = icmp_unpack(network_header[-1])
            print("ICMP :\n\tType : ", type, "\n\tCode : ", code,
                  "\n\tChecksum : ", checksum, "\n\tData : ", data)
        # TCP
        elif(network_header['upper_layer'] == 6):
            transport_header, data = transport_unpack(data, 'TCP')
            print("Transmission Control Protocol : ")
            for key, value in transport_header.items():
                print("\t", key, ' : ', value)
            prtcl = transport_header['service']
            if prtcl == 'dns':
                dns_header = app_unpack(data, 'dns')
                for key, value in dns_header.items():
                    if key != 'questions' or key != 'answers':
                        print('\t', key, ': ', value)
                print("\tquestions:")
                print("\t(domain,type name,type class)")
                for q in dns_header['questions']:
                    print(f'\t({q[0]},{q[1]},{q[2]})')
                print('\tanswers:')
                print("\t(name,type name,class name,ttl,rdlength,rdata)")
                for ans in dns_header['answers']:
                    print(
                        f'\t({ans[0]},{ans[1]},{ans[2]},{ans[3]},{ans[4]},{ans[5]})')
            else:
                print("\t", app_unpack(data, prtcl))
        # UDP
        elif(network_header['upper_layer'] == 17):
            transport_header, data = transport_unpack(data, 'UDP')
            print("User Datagram Protocol : ")
            for key, value in transport_header.items():
                print("\t", key, ' : ', value)
            prtcl = transport_header['service']
            if prtcl == 'dns':
                dns_header = app_unpack(data, 'dns')
                for key, value in dns_header.items():
                    if key != 'questions' or key != 'answers':
                        print('\t', key, ': ', value)
                print("\tquestions:")
                print("\t(domain,type name,type class)")
                for q in dns_header['questions']:
                    print(f'\t({q[0]},{q[1]},{q[2]})')
                print('\tanswers:')
                print("\t(name,type name,class name,ttl,rdlength,rdata)")
                for ans in dns_header['answers']:
                    print(
                        f'\t({ans[0]},{ans[1]},{ans[2]},{ans[3]},{ans[4]},{ans[5]})')
            else:
                print("\t", app_unpack(data, prtcl))
    else:
        print("other type")


def main(argv):
    print('*** Press ctrl^c to stop Snifing ***')
    print(" ")

    pakets = []
    try:
        # creating socket:
        conn = socket.socket(
            socket.AF_PACKET, socket.SOCK_RAW, socket.ntohs(3))
        while True:
            data, addr = conn.recvfrom(65535)
            pakets.append([time.time(), data])
            show_summay(len(pakets)-1, data)

    # keyboard interrupt occurs:
    except KeyboardInterrupt:
        # TODO : add flag for saving if you want:
        location = save_pcap(pakets)

        # see paket in detail
        print(" ")
        print(f"{ len(pakets) } pakets was sniffed and saved in { location }")
        print("Enter the number of packet you want to see it in detail (or type exit):")
        while True:
            s = input()
            if s == 'exit':
                break
            s = int(s)
            show_all(pakets[s][1])
            print(" ")
            print('Enter next packet number (or exit):')

    # something like network goes wrong:
    except:
        print('Something went wrong!')


# ------- SECTION -> checking functions-------


# Total unpack
# raw_data = 'FF00000000000000000000F0F0F'.encode()
# ether_header = data_link_unpack(raw_data)
# network_header = network_unpack(ether_header[3])
# if (network_header['upper_layer'] == 1):
#     icmp_header = icmp_unpack(network_header[-1])
# x = struct.pack('!HHHHHH',int("00",16),int("0a",16),int('95',16),int('9d',16),int('68',16),int('16',16))
# print(get_mac_addr(x))

# tcp_header  = b'\x30\x39\x00\x50' # Source Port | Destination Port
# tcp_header += b'\x00\x00\x00\x00' # Sequence Number
# tcp_header += b'\x00\x00\x00\x00' # Acknowledgement Number
# tcp_header += b'\x50\x02\x71\x10' # Data Offset, Reserved, Flags | Window Size
# tcp_header += b'\xe6\x32\x00\x00'

# udp_header = b'\x30\x39\x00\x50'
# udp_header += b'\x30\x39\x00\x50'
# print(transport_unpack(udp_header,'UDP'))

# dns_address = b'\x03\x77\x77\x77'
# dns_address += b'\x0c\x6e\x6f\x72\x74\x68\x65\x61\x73\x74\x65\x72\x6e\x03\x65\x64'
# dns_address += b'\x75\x00'

# dns_binary = b'\xdb\x42\x81\x80'
# dns_binary +=b'\x00\x01\x00\x01'
# dns_binary +=b'\x00\x00\x00\x00'
# dns_binary +=b'\x03\x77\x77\x77'
# dns_binary +=b'\x0c\x6e\x6f\x72\x74\x68\x65\x61\x73\x74\x65\x72'
# dns_binary +=b'\x6e\x03\x65\x64\x75\x00\x00\x01\x00\x01\xc0\x0c'
# dns_binary +=b'\x00\x01\x00\x01\x00\x00\x02\x58\x00\x04\x9b\x21\x11\x44'


# print(DNS(dns_binary))
# print(time.time())
