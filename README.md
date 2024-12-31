# Network Scanner

This repository contains a Python-based network scanner that leverages the Scapy library to perform various types of scans, including ICMP, ARP, TCP, and UDP scans.

## Overview

The script provides functionality to:
- Perform ICMP scans to check if a host is up.
- Execute ARP scans to identify active devices in the local network.
- Conduct TCP scans to detect open ports.
- Run UDP scans to verify if a host responds to a specific port.

Each scan type is implemented as a separate function, making the script modular and easy to extend.

## How It Works

### Command-Line Arguments
The script uses the `argparse` module to handle command-line arguments. The required arguments are:
- `-t` or `--target`: Specifies the target IP address or subnet (e.g., `192.168.1.1` or `192.168.1.0/24`).
- `-s` or `--scan-type`: Defines the type of scan to perform. Supported values are `icmp`, `arp`, `tcp`, and `udp`.

### Usage

Run the script using Python:
```bash
python network_scanner.py -t <target> -s <scan-type>
```

### Examples
- ICMP Scan for a single IP:
  ```bash
  python network_scanner.py -t 192.168.1.1 -s icmp
  ```
- ARP Scan for a subnet:
  ```bash
  python network_scanner.py -t 192.168.1.0/24 -s arp
  ```
- TCP Scan for a single IP:
  ```bash
  python network_scanner.py -t 192.168.1.1 -s tcp
  ```
- UDP Scan for a single IP:
  ```bash
  python network_scanner.py -t 192.168.1.1 -s udp
  ```

## Code Explanation

### ICMP Scan
```python
def icmp_scan(target):
    ans = sr1(IP(dst=target)/ICMP(), timeout=1, verbose=0)
    if ans:  
        return f"Host {target} is up (ICMP response received)"
    return None
```
- **`IP(dst=target)`**: Creates an IP packet with the destination address set to the target.
- **`ICMP()`**: Constructs an ICMP packet, typically used for sending echo requests (ping).
- **`sr1(IP(dst=target)/ICMP(), timeout=1, verbose=0)`**: Sends the ICMP packet and waits for a single response. Suppresses verbose output.
  - `timeout=1`: Specifies the time in seconds to wait for a response.
  - `verbose=0`: Hides Scapy's internal messages.
- If a response is received, the function returns a message indicating the host is up.

### ARP Scan
```python
def arp_scan(target_ip):
    arp_request = ARP(pdst=target_ip)
    broadcast = Ether(dst="ff:ff:ff:ff:ff:ff")
    arp_request_broadcast = broadcast/arp_request
    answered_list = srp(arp_request_broadcast, timeout=1, verbose=False)[0]
    active_hosts = []
    for element in answered_list:
        active_hosts.append(f"Host {element[1].psrc} is up (ARP response received)") 
    return active_hosts
```
- **`ARP(pdst=target_ip)`**: Creates an ARP request targeting the specified IP address or range.
- **`Ether(dst="ff:ff:ff:ff:ff:ff")`**: Constructs an Ethernet frame with a broadcast MAC address to send the ARP request to all devices in the network.
- **`broadcast/arp_request`**: Combines the Ethernet frame and ARP request into a single packet.
- **`srp(packet, timeout=1, verbose=False)`**: Sends the packet at the data link layer and waits for responses.
  - `timeout=1`: Specifies the time in seconds to wait for responses.
  - `verbose=False`: Disables verbose output.
- **`element[1].psrc`**: Extracts the source IP address from the response to identify active devices.

### UDP Scan
```python
def udp_scan(target_ip, target_port=53):
    udp_request = IP(dst=target_ip)/UDP(dport=target_port)
    ans = sr1(udp_request, timeout=1, verbose=0)
    if ans:
        return f"Host {target_ip} is up (UDP response received)"
    return None
```
- **`IP(dst=target_ip)`**: Creates an IP packet with the destination address set to the target IP.
- **`UDP(dport=target_port)`**: Constructs a UDP packet directed to the specified target port (default: 53).
- **`sr1(IP(dst=target_ip)/UDP(dport=target_port), timeout=1, verbose=0)`**: Sends the UDP packet and waits for a response.
  - `timeout=1`: Specifies the time in seconds to wait for a response.
  - `verbose=0`: Hides Scapy's internal messages.
- If a response is received, the function returns a message indicating the host is up.

### TCP Scan
```python
def tcp_scan(target_ip, target_port=80):
    tcp_syn = IP(dst=target_ip)/TCP(dport=target_port, flags="S")
    ans = sr1(tcp_syn, timeout=1, verbose=0)
    if ans and ans.haslayer(TCP) and ans.getlayer(TCP).flags == 0x12:  # SYN-ACK
        return f"Host {target_ip} is up (TCP SYN-ACK response received)"
    return None
```
- **`IP(dst=target_ip)`**: Creates an IP packet with the destination address set to the target IP.
- **`TCP(dport=target_port, flags="S")`**: Constructs a TCP packet directed to the specified target port with the SYN flag set.
- **`sr1(IP(dst=target_ip)/TCP(dport=target_port, flags="S"), timeout=1, verbose=0)`**: Sends the TCP SYN packet and waits for a single response.
  - `timeout=1`: Specifies the time in seconds to wait for a response.
  - `verbose=0`: Hides Scapy's internal messages.
- **`ans.haslayer(TCP)`**: Checks if the response contains a TCP layer.
- **`ans.getlayer(TCP).flags == 0x12`**: Verifies if the response is a SYN-ACK packet, indicating the port is open.

## Scapy Command Explanations

### `IP(dst=target)`
- Creates an IP packet with the destination address set to the target.
- Used to encapsulate transport-layer protocols like ICMP, TCP, or UDP.

### `ICMP()`
- Creates an ICMP packet. Typically used for sending echo requests (ping).

### `ARP(pdst=target_ip)`
- Constructs an ARP request packet to identify MAC addresses corresponding to the given IP addresses.

### `Ether(dst="ff:ff:ff:ff:ff:ff")`
- Creates an Ethernet frame with the destination MAC address set to the broadcast address.
- Used in ARP requests to broadcast the packet to all devices in the network.

### `sr1(packet, timeout=1, verbose=0)`
- Sends a packet and waits for a single response.
  - `timeout`: Specifies how long to wait for a response.
  - `verbose`: Suppresses output when set to `0`.

### `srp(packet, timeout=1, verbose=False)`
- Sends and receives packets at the data link layer.
- Commonly used for ARP requests where Ethernet frames are sent.

### `TCP(dport=target_port, flags="S")`
- Constructs a TCP packet with the destination port set to `target_port` and the SYN flag enabled.
- Used for initiating a TCP handshake.

### `UDP(dport=target_port)`
- Creates a UDP packet with the destination port set to `target_port`.
- Used to check if a specific UDP port is open or responsive.

## Requirements

To run the script, ensure you have the following:
- Python 3.x
- Scapy library

Install Scapy using pip:
```bash
pip install scapy
```

## Notes
- ARP scans work only on local networks.
- UDP scans may require elevated privileges.
- ICMP scans may fail if the target blocks ICMP packets.

## Disclaimer
This script is intended for educational purposes only. Ensure you have permission before scanning any network.
