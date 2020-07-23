import struct
import socket
from netaddr import *
from . import packetMaker

def data_link_unpack(data):
    dest_mac, src_mac, proto = unpack('! 6s 6s H', data[:14])
    return [get_mac_addr(dest_mac), get_mac_addr(src_mac), socket.htons(proto), data[14:]]


def network_unpack(data):
    ver = (unpack('!B', data[:8])) >> 4
    print(type(ver))
    maindata = data
    if (ver == "0100"):
        data = unpack('!BBHHHBBH4s4s', data[:20])
        header = {
            'versoin': 'IPv4',
            'header_len': (data[0] & 0xF) * 4,  # ??*4
            'TOS': data[1],
            'lenght': data[2],
            '16_bit_identifier': data[3],
            'flags': data[4] >> 13,
            'fragment_offset': data[4] & 0x1FFF,
            'TTL': data[5],
            'upper_layer': data[6],
            'header_checksum':  hex(data[7]),
            '32_bit_sourceIP': socket.inet_ntoa(data[8]),
            '32_bit_destinationIP': socket.inet_ntoa(data[9])
        }
        return [header, maindata[header['header_len']:]]
    elif (ver == "0110"):
        data = unpack('!IHBB16s16s', data[:40])
        header = {
            'versoin': 'IPv6',
            'pri': (data[0] >> 20) & 0xFF,
            'flow_table': data[0] & 0xFFFFF,
            'payload_len': data[1],
            'upper_layer': data[2],
            'hop_limit': data[3],
            '128_bit_sourceIP': socket.inet_ntoa(data[4]),
            '128_bit_destinationIP': socket.inet_ntoa(data[5])
        }
        return(header, data[40:])


def icmp_unpack(data):
    type, code, checksum = unpack('!BBH', data[:4])
    return [type, code, hex(checksum), repr(data[4:])]



def transport_unpack(data,version):
    payload = None
    header = {}
    hdr = struct.unpack
    if version=="UDP":
        payload = data[64:]
        hdr = struct.unpack('!HHHH',data[:64])
        header = {
            'protocol':'UDP',
            'src_port':hdr[0],
            'dst_port':hdr[1],
            'length':hdr[2],
            'checksum':hdr[3]
        }
        return header,payload
    elif version=='TCP':
        hdr = struct.unpack('!HHIIBBHHH',data[:160])
        header = {
            'protocol':'TCP',
            'src_port':hdr[0],
            'dst_port':hdr[1],
            'seq_number':hdr[2],
            'ack_number':hdr[3],
            'data_offset':hdr[4]>>4,  # it should multiply to 4 to be in byte
            'NS':hdr[4] & 0x1,
            'CWR':hdr[5]>>7,
            'ECE':(hdr[5]>>6) & 0x1,
            'URG':(hdr[5]>>5) & 0x1,
            'ACK':(hdr[5]>>4) & 0x1,
            'PSH':(hdr[5]>>3) & 0x1,
            'RST':(hdr[5]>>2) & 0x1,
            'SYN':(hdr[5]>>1) & 0x1,
            'FIN':hdr[5] & 0x1,
            'window_size':hdr[6],
            'checksum':hdr[7],
            'urg_ptr':hdr[8],
            'options':data[160:(32*(hdr[4]>>4))]
        }
        header['service']=packetMaker.services[str(header['dst_port'])]
        payload = data[(32*header['data_offset']):]
        return header,payload



# Total unpack
raw_data = 'FF00000000000000000000F0F0F'.encode()
ether_header = data_link_unpack(raw_data)
network_header = network_unpack(ether_header[3])
if (network_header['upper_layer'] == 1):
    icmp_header = icmp_unpack(network_header[-1])
    