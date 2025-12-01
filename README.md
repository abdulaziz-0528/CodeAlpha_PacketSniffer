# CodeAlpha_PacketSniffer

This project is a simple network packet sniffer built using Python and Scapy. It captures live network packets, extracts key information, and displays readable details such as:
 - Source and destination IP addresses
 - Protocol type (TCP/UDP)
 - Port numbers
 - Payload preview (first 50 bytes)

This project was completed as part of my CodeAlpha Cybersecurity Internship.

Features:

 - Captures real-time packets using Scapy
 - Identifies IP, TCP, and UDP packets
 - Displays source/destination details
 - Shows port numbers and protocols
 - Prints a safe preview of packet payloads
 - Captures a fixed number of packets (default: 20)

Requirements:

 - Python 3.x 
 - Scapy
 - Npcap (for Windows packet sniffing)
 - Install Scapy:
 - pip install scapy


Install Npcap (required for Windows):
https://nmap.org/npcap/

How to Run:

 - Run the script with administrator privileges:
python packet_sniffer.py


Sample output:

=== New Packet Detected ===
From: 192.168.1.10
To:   142.250.183.110
Protocol: TCP
Ports: 50532 -> 443
Payload (24 bytes): b'GET / HTTP/1.1\r\n...'
