from scapy.all import sniff, IP
from datetime import datetime

# Map protocol numbers to names
proto_map = {
    1: "ICMP",
    6: "TCP",
    17: "UDP"
}

def process_packet(packet):
    if IP in packet:
        src_ip = packet[IP].src
        dst_ip = packet[IP].dst
        proto_num = packet[IP].proto
        proto_name = proto_map.get(proto_num, f"Unknown ({proto_num})")
        timestamp = datetime.now().strftime('%H:%M:%S')

        print(f"[{timestamp}] {src_ip} → {dst_ip} | Protocol: {proto_name}")

print("🔎 Sniffing started... Press Ctrl+C to stop.")
try:
    sniff(filter="ip", prn=process_packet)
except KeyboardInterrupt:
    print("\n🛑 Sniffing stopped.")
