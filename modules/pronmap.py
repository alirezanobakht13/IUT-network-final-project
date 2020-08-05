import socket
import threading
from . import packetMaker
import time
import modules.linuxWireshark as lw
import datetime

# move this function to the better place!!
def chunkIt(seq, num):
    avg = len(seq) / float(num)
    out = []
    last = 0.0

    while last < len(seq):
        out.append(seq[int(last):int(last + avg)])
        last += avg

    return out


# --------------------SECTION : connect scan -----------------------
connect_list = []
connect_scan_runs = []


def connect_scan_thread(host, portlst, delay):
    global connect_list
    global connect_scan_runs
    print("I'm scaning :", portlst)
    for port in portlst:
        s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        try:
            s.settimeout(delay)
            s.connect((host, port))
            s.settimeout(None)
            print("Port open: " + str(port))
            s.close()
            with threading.Lock():
                connect_list.append(port)
        except socket.timeout as e:
            print(e)
        except:
            print("Port closed: " + str(port))
    connect_scan_runs.append(0)


def connect_scan(host, portlst, delay, thread_count: int = 5):
    global connect_list
    global connect_scan_runs
    if len(portlst) <= thread_count:
        connect_scan_thread(host, portlst, delay)
        temp_list = connect_list
        connect_list = []
        return temp_list
    else:
        threads = []
        if len(portlst) % thread_count == 0:
            for i in range(0, len(portlst), thread_count):
                tmp = threading.Thread(target=connect_scan_thread, args=(
                    host, portlst[i:i+thread_count], delay))
                threads.append(tmp)
        else:
            cnt = 0
            for i in range(0, len(portlst)//thread_count, thread_count):
                tmp = threading.Thread(target=connect_scan_thread, args=(
                    host, portlst[i:i+thread_count], delay))
                threads.append(tmp)
                cnt = i

            cnt += thread_count
            tmp = threading.Thread(target=connect_scan_thread, args=(
                host, portlst[cnt:], delay))
            threads.append(tmp)

        for t in threads:
            t.start()

        while True:
            if len(connect_scan_runs) >= len(threads):
                break
        connect_scan_runs = []
        temp_list = connect_list
        connect_list = []
        return temp_list


# -----------------SECTION : fin scan -----------------------------
fin_times = []
fin_thread_count = 0
fin_closed_ports = []


def fin_scan_thread(src_ip, src_port, dst_ip,delay, dst_ports: list):
    # print('scaning ports: ', dst_ports)
    global fin_times
    global fin_thread_count
    s = socket.socket(socket.AF_INET, socket.SOCK_RAW, socket.IPPROTO_RAW)
    ip = packetMaker.ipv4_header_maker(src_ip, dst_ip)
    for port in dst_ports:
        tcp = packetMaker.tcp_header_maker(port, src_ip, dst_ip, fin=1)
        packet = ip+tcp
        s.sendto(packet, (dst_ip, 0))
        t = time.time()
        with threading.Lock():
            fin_times.append((port, t))
        time.sleep(delay)
    with threading.Lock():
        fin_thread_count += 1
        # print(fin_thread_count)
    # print('scan done for ports: ', dst_ports)


def fin_rcv_thread(src_port, dst_ip,dst_ports, delay, thread_count):
    # print('start reciving!')
    global fin_times
    global fin_closed_ports
    global fin_thread_count
    s = socket.socket(socket.AF_PACKET, socket.SOCK_RAW, socket.htons(3))
    end_time = None
    recieved_ports = []
    while True:
        # checking end of the loop:
        if end_time != None:
            if time.time() > end_time:
                break
        if fin_thread_count >= thread_count:
            fin_thread_count = 0
            end_time = time.time() + delay

        # getting data:
        data, addr = s.recvfrom(65535)
        _, _, eth_proto, data = lw.data_link_unpack(data)
        if eth_proto == 8 or eth_proto == 56710:
            ip_hdr, data = lw.network_unpack(data)
            if ip_hdr['upper_layer'] == 6 and ip_hdr['32_bit_sourceIP'] == dst_ip:
                tcp, data = lw.transport_unpack(data, 'tcp')
                # print(tcp)

                # checking tcp header:
                if tcp['dst_port'] == src_port and tcp['src_port'] in dst_ports:
                    recieved_ports.append((tcp['src_port'], time.time()))

    # Checking if timeout occurs:
    for rcv_prt in recieved_ports:
        for prt in fin_times:
            if rcv_prt[0] == prt[0]:
                if rcv_prt[1] <= prt[1]+delay:
                    fin_closed_ports.append(prt[0])


def fin_scan(dst: str, port_lists: list, delay=3, thread_count=5):
    """ get destination and list of ports and runs fin scan on those port and that host,then returns list of closed ports"""
    global rcv_worker_end
    global fin_closed_ports

    # setting src and dst ip (and src port:))
    dst = socket.gethostbyname(dst)
    if dst == '127.0.0.1' or dst == socket.gethostbyname(socket.gethostname()):
        ip = socket.gethostbyname(socket.gethostname())
        port = 1234
    else:
        ip, port = packetMaker.get_ip_port()

    # making thread for send and recive
    if len(port_lists) < thread_count:
        rcv_thread = threading.Thread(
            target=fin_rcv_thread, args=(port, dst,port_lists, delay, 1))
        rcv_thread.start()
        time.sleep(0.1)
        send_thread = threading.Thread(
            target=fin_scan_thread, args=(ip, port, dst,delay, port_lists))
        send_thread.start()
    else:
        chunked_ports = chunkIt(port_lists, thread_count)
        rcv_thread = threading.Thread(target=fin_rcv_thread, args=(
            port, dst,port_lists, delay, len(chunked_ports)))
        rcv_thread.start()
        time.sleep(0.1)
        for ports in chunked_ports:
            t = threading.Thread(target=fin_scan_thread,
                                 args=(ip, port, dst,delay, ports))
            t.start()

    rcv_thread.join()
    tmp = fin_closed_ports
    fin_closed_ports = []
    return list(set(tmp))



#--------------------SECTION : WINDOW SCAN -------------------------
window_times = []
window_thread_count = 0
window_responses = [] #pair of port number and a number which if False means close and True means open
def window_send_thread(src_ip,src_port,dst_ip,dst_ports:list,delay):
    global window_times
    global window_thread_count
    s = socket.socket(socket.AF_INET, socket.SOCK_RAW, socket.IPPROTO_RAW)
    ip = packetMaker.ipv4_header_maker(src_ip, dst_ip)
    for port in dst_ports:
        tcp = packetMaker.tcp_header_maker(port, src_ip, dst_ip, ack=1)
        packet = ip+tcp
        s.sendto(packet, (dst_ip, 0))
        t = time.time()
        with threading.Lock():
            window_times.append((port, t))
        time.sleep(delay)
    with threading.Lock():
        window_thread_count += 1


def window_rcv_thread(src_port,dst_ip,dst_ports:list,delay,thread_count):
    global window_times
    global window_thread_count
    global window_responses
    s = socket.socket(socket.AF_PACKET, socket.SOCK_RAW, socket.htons(3))
    end_time = None
    recieved_ports = [] # pair of port number and a number which if False means close and True means open
    while True:
        # checking end of the loop:
        if end_time != None:
            if time.time() > end_time:
                break
        if window_thread_count >= thread_count:
            window_thread_count = 0
            end_time = time.time() + delay
        
        # getting data:
        data, addr = s.recvfrom(65535)
        _, _, eth_proto, data = lw.data_link_unpack(data)
        if eth_proto == 8 or eth_proto == 56710:
            ip_hdr, data = lw.network_unpack(data)
            if ip_hdr['upper_layer'] == 6 and ip_hdr['32_bit_sourceIP'] == dst_ip:
                tcp, data = lw.transport_unpack(data, 'tcp')
                # print(tcp)

                # checking tcp header:
                if tcp['dst_port'] == src_port and (tcp['src_port'] in dst_ports) and tcp['RST'] == 1:
                    if tcp['window_size'] == 0:
                        recieved_ports.append((tcp['src_port'],time.time(),False))
                    else:
                        recieved_ports.append((tcp['src_port'],time.time(),True))
    
    # drop delayed packets:
    for rcv_prt in recieved_ports:
        for prt in window_times:
            if prt[0] == rcv_prt[0]:
                if rcv_prt[1]<=prt[1]+delay:
                    window_responses.append((rcv_prt[0],rcv_prt[2]))


def window_scan(dst,port_lists,delay =3 ,thread_count= 5):
    """ get destination and list of ports and runs fin scan on those port and that host,then returns list of open and closed ports"""
    global window_responses

    # setting src and dst ip (and src port:))
    dst = socket.gethostbyname(dst)
    if dst == '127.0.0.1' or dst == socket.gethostbyname(socket.gethostname()):
        ip = socket.gethostbyname(socket.gethostname())
        port = 1234
    else:
        ip, port = packetMaker.get_ip_port()

    # making thread for send and recive
    if len(port_lists) < thread_count:
        rcv_thread = threading.Thread(
            target=window_rcv_thread, args=(port, dst,port_lists, delay, 1))
        rcv_thread.start()
        time.sleep(0.1)
        send_thread = threading.Thread(
            target=window_send_thread, args=(ip, port, dst, port_lists,delay))
        send_thread.start()
    else:
        chunked_ports = chunkIt(port_lists, thread_count)
        rcv_thread = threading.Thread(target=window_rcv_thread, args=(
            port, dst,port_lists, delay, len(chunked_ports)))
        rcv_thread.start()
        time.sleep(0.1)
        for ports in chunked_ports:
            t = threading.Thread(target=window_send_thread,
                                 args=(ip, port, dst, ports,delay))
            t.start()
    
    rcv_thread.join()
    tmp = window_responses
    window_responses = []
    return list(set(tmp))


# check function:
def check():
    host, port
    hostaddr = socket.gethostbyname(hostname)
    print(socket.gethostbyname_ex(hostname))
    print(hostname)
    print(hostaddr)
    example = socket.gethostbyname('www.example.com')
    print(example)
    s = socket.socket(socket.AF_INET, socket.SOCK_RAW, socket.IPPROTO_RAW)
    print(s.getsockname())
    tcp = packetMaker.tcp_header_maker(80, host, example, syn=1, src_port=6789)
    ip = packetMaker.ipv4_header_maker(host, example)
    packet = ip+tcp
    print(packet)
    s.sendto(packet, (example, 0))

    # while True:
    #     data = s.recvfrom(65535)
    #     dest_mac, src_mac, eth_proto, data = lw.data_link_unpack(data)
    #     if eth_proto == 8 or eth_proto == 56710:
    #         network_hdr , data = lw.network_unpack(data)
    #         if network_hdr['upper_layer']== 6:
    #             tcp_hdr , data = lw.transport_unpack(data,'tcp')
    #             if tcp_hdr['src_port'] == 6789 or tcp_hdr['dst_port'] == 6789:
    #                 print(network_hdr)
    #                 print(tcp_hdr)

    return packet




message = f"""by this command, you can scan any range of ports of your desire host.
notice that scanning ports is illegal, so don't do this if it's not necessary.
command should be like below format (root access needed):
sudo python(3) babyshark scan -h [hostname] -p [sp]-[ep] [scan-type] -d [delay] -t [# of threads]
hostname: fqdn or ip address of destination host.
sp: start port.
ep: end port.
scan-type:
    -CS: connect scan
    -SS: syn scan
    -AS: ack scan
    -FS: fin scan
    -WS: window scan
delay(optional): amount of time in seconds to be delayed for sending next packet and also waiting for answers. defualt=3.
# of threads(optional): number of threads sending packet simultaneously. it should be greater or equal to 1 and smaller than 8 (more than 8 thread is not effecient). defualt=5
or run python(3) babyshark scan --help to see this message again!"""


def main(argv:list):
    if len(argv)==1:
        print("if you need help use python(3) babyshark scan --help.")
    elif '--help' in argv:
        print(message)
    else:
        try:
            #getting all parameters:
            dst = argv[argv.index('-h')+1]
            sp,ep = argv[argv.index('-p')+1].split('-')
            sp,ep = int(sp),int(ep)
            port_lists = [*range(sp,ep+1)]
            delay = float(argv[argv.index('-d')+1]) if '-d' in argv else 3
            thread_count = int(argv[argv.index('-t')+1]) if '-t' in argv else 5

            #checking senarios:
            if '-CS' in argv:
                start_time = time.time()
                connected_list = connect_scan(dst,port_lists,delay,thread_count)
                print(f'Connect scan of {dst}({socket.gethostbyname(dst)}) started at {datetime.datetime.fromtimestamp(start_time)} ')
                print(' ')
                end_time = time.time()
                if len(connected_list) == 0:
                    print(f'all {ep-sp+1} ports were close.')
                else:
                    print(f"{'PORT':<15}{'STATUS':^10}{'SERVICE':>15}")
                    for cnn in connected_list:
                        service = packetMaker.services.get(str(cnn),"unknown")
                        print(f"{cnn:<15}{'open':^10}{service:>15}")
                print(' ')
                print(f'connect scan finished in {end_time-start_time} secs.')
                

            elif '-SS' in argv:
                pass # TODO : add this part


            elif '-AS' in argv:
                pass


            elif '-FS' in argv:
                start_time = time.time()
                print(f'fin scan of {dst}({socket.gethostbyname(dst)}) started at {datetime.datetime.fromtimestamp(start_time)} ')
                print(' ')
                closed_ports = fin_scan(dst,port_lists,delay,thread_count)
                opend_ports = list(set(port_lists).difference(set(closed_ports)))
                ################### TODO : fin scan should accept icmp too


            elif '-WS' in argv:
                start_time = time.time()
                print(f'window scan of {dst}({socket.gethostbyname(dst)}) started at {datetime.datetime.fromtimestamp(start_time)} ')
                print(' ')

                open_closed = window_scan(dst,port_list,delay,thread_count)
                op_count = 0
                for port in open_closed:
                    if port[1]:
                        op_count+=1
                
                if op_count == len(port_lists):
                    print(f'all {ep-sp+1} ports are open')
                elif op_count == 0 and len(open_closed) == 0:
                    print(f'all {ep-sp+1} ports are filtered')
                elif op_count == 0 and len(open_closed) == len(port_lists):
                    print(f'all {ep-sp+1} ports are closed')
                else:
                    op_ports = []
                    for tmp in open_closed:
                        op_ports.append(tmp[0])
                    print(f"{'PORT':<15}{'STATUS':^10}{'SERVICE':>15}")
                    for port in port_lists:
                        service = packetMaker.services.get(str(cnn),"unknown")
                        if port in op_ports ##########################################################################################################################3



        except:
            pass

        