import psutil
import wmi
import os
import time


sus_open_ports = [22, 23, 21, 3389, 5900, 5985, 5986, 1433, 27017, 6379, 5432, 3306, 53]
my_ports = []
def getting_my_open_ports_list():
    connections = psutil.net_connections(kind='inet')
    my_ports = [conn.laddr.port for conn in connections if conn.status == psutil.CONN_LISTEN]
    my_ports = list(set(my_ports))
    my_ports.sort()
    print(my_ports)

def checking_if_new_sus_open_ports_opened():
    connections = psutil.net_connections(kind='inet')
    ports = [conn.laddr.port for conn in connections if conn.status == psutil.CONN_LISTEN]
    ports = list(set(ports))
    for port in ports:
        if port not in my_ports and port in sus_open_ports:
            print(f"syspicous new port opened: {port}")