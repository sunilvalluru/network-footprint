"""net.py - raw socket + internal references (Python)."""
import socket

# OUT/BOTH: connect to an external log-forwarding host over TCP (public documentation IP)
def forward_logs(lines):
    s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    s.connect(("54.230.0.10", 6514))   # syslog over TCP
    for line in lines:
        s.sendall(line.encode())
    ack = s.recv(1024)                   # small inbound ack
    s.close()
    return ack

# Internal-only references (private ranges / localhost) - not external data flow
CACHE_HOST = "192.168.10.5"     # internal Redis, private range
LOCAL_API = "http://localhost:8080/health"
LOOPBACK = "127.0.0.1"
