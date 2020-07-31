import sys
import socket
import time
from modules import linuxWireshark as lw

if __name__=="__main__":
    pass


# SECTION ---> test:
# conn = socket.socket(socket.AF_PACKET,socket.SOCK_RAW,socket.ntohs(3))
# pkts = []
# while True:
#     data,addr = conn.recvfrom(65535)
#     # pkts.append([time.time(),raw_data])
#     src_mac,dst_mac,proto,data = lw.data_link_unpack(data)
#     # print(f'src mac is {src_mac} - dst mac is {dst_mac} - proto is {proto}.')
#     if proto == 8:
#         ip_header , data = lw.network_unpack(data)
#         # print('ip header is : ----------------')
#         # print(ip_header)
#         tcpheader = None
#         if ip_header['upper_layer'] == 6 or ip_header['upper_layer'] == 17:
#             if ip_header['upper_layer'] == 6:
#                 tcpheader,data = lw.transport_unpack(data,'TCP')
#             elif ip_header['upper_layer'] == 17:
#                 tcpheader,data = lw.transport_unpack(data,'UDP')
#             # print('TCP header is : -----------------')
#             # print(tcpheader)
#             # print(lw.app_unpack(data,tcpheader['service']))
#             if tcpheader['service'] == 'http':

# for pkt in pkts:
#     data = pkt[1]
#     src_mac,dst_mac,proto,data = lw.data_link_unpack(data)
#     print(f'src mac is {src_mac} - dst mac is {dst_mac} - proto is {proto}.')
#     if proto == 8:
#         ip_header , data = lw.network_unpack(data)
#         print('ip header is : ----------------')
#         print(ip_header)
#         tcpheader = None
#         if ip_header['upper_layer'] == 6 or ip_header['upper_layer'] == 17:
#             if ip_header['upper_layer'] == 6:
#                 tcpheader,data = lw.transport_unpack(data,'TCP')
#             elif ip_header['upper_layer'] == 17:
#                 tcpheader,data = lw.transport_unpack(data,'UDP')
#             print('TCP header is : -----------------')
#             print(tcpheader)
#             print(lw.app_unpack(data,tcpheader['service'])['content'])



print(bin(1))