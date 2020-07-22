import struct
import socket
from . import packetMaker

def data_link_unpack(data):
    dest_mac, src_mac, proto = unpack('! 6s 6s H', data[:14])
    return [get_mac_addr(dest_mac), get_mac_addr(src_mac), socket.htons(proto), data[14:]]

def network_unpack(data):
    maindata = data
    data = unpack('!BBHHHBBH4s4s', data[:20])
    return [(data[0] >> 4), (data[0] & 0xF) * 4, data[1], data[2],
    data[3], data[4] >> 13, data[4] & 0x1FFF, data[5],
    data[6], hex(data[7]), socket.inet_ntoa(data[8]),
    socket.inet_ntoa(data[9]), maindata[((data[0] & 0xF) * 4):]]
    

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