import psutil
import wmi
import os
import time
import socket
import threading
import selectors

sus_open_ports = [22, 23, 21, 3389, 5900, 5985, 5986, 1433, 27017, 6379, 5432, 3306, 53]
ip_dict = {}
honeypot_sockets = []
sel = selectors.DefaultSelector()

def getting_my_open_ports_list():
    connections = psutil.net_connections(kind='inet')
    my_ports = [conn.laddr.port for conn in connections if conn.status == psutil.CONN_LISTEN]
    my_ports = list(set(my_ports))
    my_ports.sort()
    print(my_ports)
    return my_ports

my_ports = getting_my_open_ports_list()
def checking_if_new_sus_open_ports_opened():
    connections = psutil.net_connections(kind='inet')
    ports = [conn.laddr.port for conn in connections if conn.status == psutil.CONN_LISTEN]
    ports = list(set(ports))
    for port in ports:
        if port not in my_ports and port in sus_open_ports:
            return "MEDIUM",f"syspicous new port opened: {port}"
    return None, None

def detect_scanners_setup():

    #print("[INFO] Setting up honeypot listeners...")
    for port in sus_open_ports:
        try:
            s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            s.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
            s.bind(("0.0.0.0", port))
            s.listen(5)
            s.setblocking(False)
            sel.register(s, selectors.EVENT_READ, data=port)
            honeypot_sockets.append(s)
            #print(f"[HONEYPOT] Listening on port {port}")
        except OSError:
            print(f"[WARN] Could not bind port {port} (already in use?)")

def honeypot_event_loop():
    #print("[INFO] Honeypot active. Waiting for scanners...")
    while True:
        events = sel.select(timeout=1)
        for key, _ in events:
            listener_socket = key.fileobj
            port = key.data
            try:
                conn, addr = listener_socket.accept()
                conn.close()
                return "LOW",f"[SCAN DETECTED] {addr[0]} tried connecting to honeypot port {port}"
            except BlockingIOError:
                pass
        time.sleep(0.5)

total_broken_connections = 0
time_in_seconds = 0

def rate_monitoring():
    global total_broken_connections, time_in_seconds
    connections = psutil.net_connections(kind='inet')
    broken_connections = [connection for connection in connections if connection.status == "SYN_RECV"]
    avg = 0
    if(time_in_seconds == 0):
        avg = total_broken_connections
    else:
        avg = total_broken_connections/time_in_seconds
    if(len(broken_connections) > avg * 5):
        return "MEDIUM","spike detected"
    time_in_seconds+=1
    total_broken_connections += len(broken_connections)
    return None, None
