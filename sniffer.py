#!/usr/bin/env python3
"""
Bat-Sniffer: A lightweight network sniffer with Layer 7 parsing and alerts.
Built for educational purposes and local lab testing.

Examples:
    sudo python3 sniffer.py -i lo
    sudo python3 sniffer.py -i eth0 --no-alerts
"""

import argparse
from datetime import datetime
import sys
from scapy.all import sniff, IP, IPv6, TCP, UDP, DNS, DNSQR, Raw, conf

# Suppress Scapy startup and warning noise
conf.verb = 0


def parse_args():
    parser = argparse.ArgumentParser(description="Bat-Sniffer: Layer 7 Network Sniffer & Alert System")
    parser.add_argument("-i", "--interface", default="lo",
                        help="Network interface to sniff on (default: lo; macOS: lo0)")
    parser.add_argument("--no-alerts", action="store_true",
                        help="Disable loud cleartext password alerts and terminal bells")
    return parser.parse_args()


def process_packet(packet, alert_on_password=True):
    """Analyzes each packet and prints the results."""
    
    # Extract IP layer details uniformly
    has_ip = packet.haslayer(IP)
    has_ipv6 = packet.haslayer(IPv6)
    
    if not (has_ip or has_ipv6):
        return

    src_ip = packet[IP].src if has_ip else packet[IPv6].src
    dst_ip = packet[IP].dst if has_ip else packet[IPv6].dst
    timestamp = datetime.now().strftime('%H:%M:%S')

    # 1. Look for DNS Traffic (UDP Port 53)
    if packet.haslayer(UDP) and packet.haslayer(DNS) and packet.haslayer(DNSQR):
        try:
            query = packet[DNSQR].qname.decode('utf-8', errors='ignore').rstrip('.')
            print(f"[{timestamp}] [DNS] {src_ip} -> {query}")
        except Exception:
            pass

    # 2. Look for HTTP Traffic (TCP / Raw payload)
    if packet.haslayer(TCP) and packet.haslayer(Raw):
        try:
            payload = packet[Raw].load.decode('utf-8', errors='ignore')
        except Exception:
            return

        # Check strictly for valid HTTP request methods at the start of the payload
        if payload.startswith(("GET ", "POST ", "PUT ", "DELETE ")):
            lines = payload.split('\r\n')
            request_line = lines[0] if lines else payload.split('\n')[0]
            
            print(f"[{timestamp}] [HTTP] {src_ip} -> {dst_ip} | {request_line}")
            
            # --- THE REAL-TIME ALERT (Improved Detection) ---
            if payload.startswith("POST") and alert_on_password:
                # Split the payload at the double newline to separate headers from the body
                parts = payload.split('\r\n\r\n')
                if len(parts) > 1:
                    body = parts[1].lower()
                    if "password" in body or "passwd" in body:
                        print(f"\a\n\033[91m" + "!" * 50)
                        print("[CRITICAL ALERT] CLEARTEXT PASSWORD DETECTED IN BODY!")
                        print(payload)
                        print("!" * 50 + "\033[0m\n")


def main():
    args = parse_args()
    
    print("==================================================")
    print("Bat-Sniffer: Layer 7 Parser & Alert System")
    print(f"Listening on interface: {args.interface}")
    print("==================================================")
    print("Press Ctrl+C to stop.\n")
    
    # Kernel-level filter keeps your script fast by ignoring irrelevant traffic
    bpf_filter = "udp port 53 or tcp port 80"
    
    try:
        sniff(
            iface=args.interface,
            filter=bpf_filter,
            prn=lambda pkt: process_packet(pkt, alert_on_password=not args.no_alerts),
            store=False,
            count=0
        )
    except PermissionError:
        print("\n[!] Permission Denied. Run with sudo.")
    except KeyboardInterrupt:
        print("\n[+] Sniffer stopped by user. Exiting...")


if __name__ == "__main__":
    main()
