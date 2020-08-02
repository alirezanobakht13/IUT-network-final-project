import sys
import socket
import time
from modules import linuxWireshark as lw
from modules import pronmap


help_message = f"""Welcom to babyshark ^ ^
this powerfull program can do three things for you:
Sniff:
    by running "python(3) {sys.argv[0]} sniff" you can sniff pakets like wireshark.
    (if need help for this command run "python(3) {sys.argv[0]} sniff --help")
    notice that if you want to use this command you should have super user access,
    so run like this: "sudo python(3) {sys.argv[0]} sniff"
scan:
    scan ports of any host you want even better than nmap (no, not at all!).
    (if need help for this command run "python(3) {sys.argv[0]} scan --help")
autoresponse:
    response pakets automatically!
    (if need help for this command run "python(3) {sys.argv[0]} autoresponse --help")
or you can run "python(3) {sys.argv[0]} --help" to see this message again!!
"""
if __name__ == "__main__":
    argv = sys.argv
    if len(argv) == 1:
        print(
            f'bad command. run "python(3) {argv[0]} --help" if you need help')

    elif argv[1] == 'sniff':
        lw.main(argv)
    elif argv[1] == 'scan':
        pass  # TODO add scan cli here
    elif argv[1] == 'autoresponse':
        pass  # TODO add autoresponse cli here
    elif argv[1] == '--help':
        print(help_message)
    else:
        print(
            f'command not found.  run "python(3) {argv[0]} --help" if you need help')

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


# def connect_scan(host, portlst):
#     s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
#     lst = []
#     for port in portlst:
#         try:
#             s.connect((host, port))
#             start_time = time.time()
#             print("Port open: " + str(port))
#             s.close()
#             lst.append(port)
#         except:
#             print("Port closed: " + str(port))
#     return lst


# host = "10.10.10.1"
# portlst = [21, 22, 80, 8080]
# lst = []
# lst = connect_scan(host, portlst)
# print(lst)
