# Network Packet Analyzer (GUI)

A Python-based network sniffer with a graphical user interface for capturing and analyzing packets on your network interface. Built for educational and ethical use only.

## Features
- **Live Packet Capture:** Start and stop sniffing with a button.
- **Custom Packet Count:** Set the number of packets to capture (or sniff continuously).
- **Detailed Display:** Shows source/destination IPs, protocol (TCP, UDP, ICMP, etc.), and readable payloads.
- **Scrollable Output:** View all captured packet details in a scrollable text area.
- **User-friendly GUI:** Built with `tkinter` for ease of use.

## Requirements
- Python 3.x
- [scapy](https://scapy.net/) library for packet capture
- `tkinter` (included with standard Python)

Install scapy with:
```bash
pip install scapy
```

## Usage
1. **Run as administrator/root** (required for network sniffing):
    ```bash
    python packet_analyzer.py
    ```
2. Enter the number of packets to capture (0 = continuous).
3. Click **Start Sniffing** to begin. Click **Stop** to end.
4. Captured packet details will appear in the window.

## How It Works
- Captures packets on the default network interface.
- Displays source and destination IP addresses, protocol, and payload (if available).
- Payloads are shown in readable form when possible, or as raw bytes.

## Ethical Notice
> **This tool is for educational and ethical use only. Unauthorized network sniffing is illegal and unethical. Always obtain explicit permission before using this tool on any network.**

---
*Created as part of the Prodigy InfoTech internship tasks.* 
