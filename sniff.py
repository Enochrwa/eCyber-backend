from scapy.all import sniff, IP, TCP, UDP, ICMP
from datetime import datetime
import logging
import os

# === Configuration ===
LOG_FILE = "packet_logs.txt"
INTERFACE = None  # Set to "eth0", "wlan0", etc., or None for default
PACKET_COUNT = 0  # 0 = capture forever

# === Logging Setup ===
if os.path.exists(LOG_FILE):
    os.remove(LOG_FILE)

logging.basicConfig(
    filename=LOG_FILE,
    filemode="a",
    format="%(asctime)s - %(message)s",
    level=logging.INFO,
)


# === Packet Parser ===
def process_packet(packet):
    try:
        timestamp = datetime.now().strftime("%Y-%m-%d %H:%M:%S")

        if IP in packet:
            ip_layer = packet[IP]
            proto = ip_layer.proto
            src_ip = ip_layer.src
            dst_ip = ip_layer.dst

            log_msg = f"[{timestamp}] IP Packet: {src_ip} -> {dst_ip} | "

            if TCP in packet:
                log_msg += f"TCP {packet[TCP].sport} -> {packet[TCP].dport}"
            elif UDP in packet:
                log_msg += f"UDP {packet[UDP].sport} -> {packet[UDP].dport}"
            elif ICMP in packet:
                log_msg += f"ICMP Type: {packet[ICMP].type}"
            else:
                log_msg += f"Protocol: {proto}"

        else:
            log_msg = f"[{timestamp}] Non-IP Packet: {packet.summary()}"

        print(log_msg)
        logging.info(log_msg)

    except Exception as e:
        print(f"[ERROR] Failed to process packet: {e}")


# === Start Sniffing ===
def start_sniffer():
    print("[*] Starting packet sniffer...")
    try:
        sniff(iface=INTERFACE, prn=process_packet, store=False, count=PACKET_COUNT)
    except KeyboardInterrupt:
        print("\n[!] Sniffer stopped by user.")
    except Exception as e:
        print(f"[ERROR] Sniffer error: {e}")


if __name__ == "__main__":
    start_sniffer()
