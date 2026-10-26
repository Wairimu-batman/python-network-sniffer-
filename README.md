# Bat-Sniffer

A lightweight, high-performance network sniffer built in Python using Scapy. It parses Layer 7 application protocols (DNS, HTTP) and features a real-time alert system for detecting cleartext credentials.

## Features
- **Kernel-Level BPF Filtering:** Uses Berkeley Packet Filter (BPF) to drop irrelevant traffic at the OS level, ensuring high performance and zero packet loss under load.
- **Layer 7 Parsing:** Decodes DNS queries and HTTP requests (GET, POST, PUT, DELETE) on the fly.
- **IPv4 & IPv6 Support:** Handles both IP formats seamlessly.
- **Real-time Alerts:** Flashes a red terminal warning if a cleartext password is detected in the body of an HTTP POST request.
- **CLI Support:** Accepts command-line arguments for interface selection and toggling alerts.

## Prerequisites
- Python 3
- Scapy (`pip install scapy`)
- Root/Sudo privileges (required to access raw sockets)

## Usage

Run the tool with sudo, specifying your network interface (e.g., `lo` for localhost, `wlan0` for Wi-Fi):

```bash
sudo python3 sniffer.py -i lo

sudo python3 sniffer.py -i lo --no-alerts (monitor traffic silently)
