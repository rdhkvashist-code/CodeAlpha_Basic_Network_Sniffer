from scapy.all import sniff, IP, TCP, UDP
from datetime import datetime

# =========================================
# CodeAlpha Cyber Security Internship
# Task 1: Basic Network Sniffer
# Author: Radhika
# =========================================

def analyze_packet(packet):

    # Check if packet contains IP layer
    if packet.haslayer(IP):

        timestamp = datetime.now().strftime("%H:%M:%S")

        src_ip = packet[IP].src
        dst_ip = packet[IP].dst
        protocol = packet[IP].proto

        print("\n" + "=" * 60)
        print(f"[+] Packet Captured At : {timestamp}")
        print(f"[+] Source IP          : {src_ip}")
        print(f"[+] Destination IP     : {dst_ip}")

        # TCP Protocol
        if packet.haslayer(TCP):
            print("[+] Protocol            : TCP")
            print(f"[+] Source Port         : {packet[TCP].sport}")
            print(f"[+] Destination Port    : {packet[TCP].dport}")

        # UDP Protocol
        elif packet.haslayer(UDP):
            print("[+] Protocol            : UDP")
            print(f"[+] Source Port         : {packet[UDP].sport}")
            print(f"[+] Destination Port    : {packet[UDP].dport}")

        else:
            print(f"[+] Protocol Number     : {protocol}")

        print("=" * 60)


def main():

    print("=" * 60)
    print("        BASIC NETWORK PACKET SNIFFER")
    print("          CodeAlpha Internship")
    print("=" * 60)

    print("\n[*] Sniffing Started...")
    print("[*] Waiting For Network Traffic...\n")

    # Capture 10 packets
    sniff(prn=analyze_packet, store=False, count=10)


if __name__ == "__main__":
    main()