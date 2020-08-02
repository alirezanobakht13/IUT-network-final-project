import socket
import threading
from . import packetMaker
import time

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


# prtlst = [1, 21, 3, 80, 403, 443, 23, 404, 88]
# print(connect_scan('www.google.com', prtlst, 10))
