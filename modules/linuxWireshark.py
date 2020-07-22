import struct

def data_link_unpack(data)
    dest_mac, src_mac, proto = unpack('! 6s 6s H', data[:14])
    return [get_mac_addr(dest_mac), get_mac_addr(src_mac), socket.htons(proto), data[14:]]

def network_unpack(data)
    maindata = data
    data = unpack('!BBHHHBBH4s4s', data[:20])
    return [(data[0] >> 4), (data[0] & 0xF) * 4, data[1], data[2],
    data[3], data[4] >> 13, data[4] & 0x1FFF, data[5],
    data[6], hex(data[7]), socket.inet_ntoa(data[8]),
    socket.inet_ntoa(data[9]), maindata[((data[0] & 0xF) * 4):]]
    
    