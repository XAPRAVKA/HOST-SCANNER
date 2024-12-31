# Host Scanner

This project demonstrates a simple network scanner built using Python and Scapy. It supports multiple scanning techniques, including ICMP, ARP, TCP, and UDP scans. Below is an explanation of the code and its functionality.

## Features
- **ICMP Scan**: Sends an ICMP echo request to check if a host is reachable.
- **ARP Scan**: Uses ARP to identify active hosts in the local network.
- **TCP Scan**: Sends a TCP SYN packet to check if a port is open.
- **UDP Scan**: Sends a UDP packet to check if a host responds.

## Code Explanation

### Import Statements
```python
import argparse
from scapy.all import IP, ICMP, ARP, TCP, UDP, sr1, Ether, srp
```
- **`argparse`**: Handles command-line arguments.
- **`scapy.all`**: Provides classes and methods for packet construction and scanning.

### ICMP Scan
```python
def icmp_scan(target):
    ans = sr1(IP(dst=target)/ICMP(), timeout=1, verbose=0)
    if ans:  
        return f"Host {target} is up (ICMP response received)"
    return None
```
- Sends an ICMP echo request to the target.
- Checks if a response is received within 1 second.

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
- Constructs an ARP request and broadcasts it to the network.
- Captures responses to identify active hosts.

### UDP Scan
```python
def udp_scan(target_ip, target_port=53):
    udp_request = IP(dst=target_ip)/UDP(dport=target_port)
    ans = sr1(udp_request, timeout=1, verbose=0)
    if ans:
        return f"Host {target_ip} is up (UDP response received)"
    return None
```
- Sends a UDP packet to the target port.
- Waits for a response within 1 second.

### TCP Scan
```python
def tcp_scan(target_ip, target_port=80):
    tcp_syn = IP(dst=target_ip)/TCP(dport=target_port, flags="S")
    ans = sr1(tcp_syn, timeout=1, verbose=0)
    if ans and ans.haslayer(TCP) and ans.getlayer(TCP).flags == 0x12:  # SYN-ACK
        return f"Host {target_ip} is up (TCP SYN-ACK response received)"
    return None
```
- Sends a TCP SYN packet to the target port.
- Checks if a SYN-ACK response is received, indicating the port is open.

### Command-Line Argument Parsing
```python
parser = argparse.ArgumentParser(description="Network Scanner")
parser.add_argument("-t", "--target", required=True, help="Target IP or subnet (e.g., 192.168.1.1 or 192.168.1.0/24)")
parser.add_argument("-s", "--scan-type", required=True, choices=['icmp', 'arp', 'tcp', 'udp'], help="Type of scan to perform")
args = parser.parse_args()
```
- Parses command-line arguments for the target and scan type.

### Target Handling
```python
if "/" in target_ip:
    from ipaddress import ip_network
    targets = [str(ip) for ip in ip_network(target_ip, strict=False).hosts()]
else:
    targets = [target_ip]
```
- Determines if the target is a single IP or a subnet.
- If it is a subnet, generates a list of all valid host IPs.

### Scan Type Selection and Execution
```python
if scan_type == 'icmp':
    scan_func = icmp_scan
elif scan_type == 'arp':
    scan_func = arp_scan
elif scan_type == 'tcp':
    scan_func = tcp_scan
elif scan_type == 'udp':
    scan_func = udp_scan

for target in targets:
    result = scan_func(target)
    if result:  
        print(result)
```
- Maps the user-specified scan type to the appropriate function.
- Performs the scan for each target and prints results for active hosts.

### Suppressing Scapy Verbosity
```python
from scapy.all import conf
conf.verb = 0 
```
- Disables Scapy's verbose output to keep the program's output clean.

## Usage
Run the script with the following command:
```bash
python scanner.py -t <target_ip_or_subnet> -s <scan_type>
```

### Examples
- ICMP Scan for a single IP:
  ```bash
  python scanner.py -t 192.168.1.1 -s icmp
  ```
- ARP Scan for a subnet:
  ```bash
  python scanner.py -t 192.168.1.0/24 -s arp
  ```
- TCP Scan for a single IP:
  ```bash
  python scanner.py -t 192.168.1.1 -s tcp
  ```
- UDP Scan for a single IP:
  ```bash
  python scanner.py -t 192.168.1.1 -s udp
  ```

## Requirements
- Python 3.x
- Scapy library

Install Scapy using pip:
```bash
pip install scapy
