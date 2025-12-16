# EtherEye - Network Packet Analyzer

A powerful packet sniffer and network analysis tool with a modern GUI interface.

![EtherEye](screenshot.png)

## Features

- **Real-time Packet Capture**: Capture network traffic on any interface
- **Protocol Decoding**: Support for Ethernet, IP, TCP, UDP, ICMP, ARP, and more
- **Advanced Filtering**: BPF syntax and display filters
- **Session Management**: Save and load capture sessions
- **Export Capabilities**: Export to PCAP, CSV, JSON, and TXT formats
- **Dark Theme**: Modern, dark-themed UI for comfortable use
- **History Log**: Automatic session history with SQLite storage

## Requirements

- Python 3.8+
- PyQt6
- Scapy
- SQLite3 (included with Python)

## Installation

1. Clone the repository:
```bash
git clone https://github.com/YOUR_USERNAME/EtherEye.git
cd EtherEye