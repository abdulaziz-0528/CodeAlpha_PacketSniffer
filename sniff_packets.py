from scapy.all import sniff, IP, TCP, UDP, Raw

def display_packet(pkt):
    """Print readable information for each captured packet."""
    
    if pkt.haslayer(IP):
        src = pkt[IP].src
        dst = pkt[IP].dst

        print("\n=== New Packet Detected ===")
        print(f"From: {src}")
        print(f"To:   {dst}")

        if pkt.haslayer(TCP):
            print(f"Protocol: TCP")
            print(f"Ports: {pkt[TCP].sport} -> {pkt[TCP].dport}")

        elif pkt.haslayer(UDP):
            print(f"Protocol: UDP")
            print(f"Ports: {pkt[UDP].sport} -> {pkt[UDP].dport}")

        else:
            print("Protocol: Other/Unknown")

        if pkt.haslayer(Raw):
            payload = pkt[Raw].load
            print(f"Payload ({len(payload)} bytes): {payload[:50]!r}")  # show only first 50 bytes

print("Starting capture... Press CTRL+C to stop.\n")
sniff(prn=display_packet, count=20)
