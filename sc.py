import socket
from scapy.all import get_if_list
import psutil

# Interfaces avec noms lisibles
psutil_ifaces = psutil.net_if_addrs().keys()
scapy_ifaces = get_if_list()

print("Interfaces Scapy :", scapy_ifaces)
print("Interfaces lisibles :", list(psutil_ifaces))

for iface, addrs in psutil.net_if_addrs().items():
    print(iface, [a.address for a in addrs if a.family == socket.AF_INET])