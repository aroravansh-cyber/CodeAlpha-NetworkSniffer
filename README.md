<div align="center">

<img src="assets/CodeAlpha-logo.png" width="250" alt="CodeAlpha Logo"/>

  <br/>

  <img src="https://readme-typing-svg.demolab.com?font=Fira+Code&size=44&pause=1000&color=1E90FF&center=true&vCenter=true&width=500&lines=Network+Sniffer" alt="Network Sniffer"/>

</div>

---

## About the Project

**Network Sniffer** is **Project #1** of my **CodeAlpha Cyber Security Internship**.

This tool captures live network traffic and analyzes packets flowing through a network interface. It inspects headers of captured packets to extract useful information such as **source/destination IP addresses, protocols, and payload data**, helping to understand how data moves across a network and how basic packet analysis works.

---

## Features

- 🔍 Real-time packet capturing on a selected network interface
- 📦 Protocol identification (TCP, UDP, ICMP, etc.)
- 🌐 Source & destination IP / port extraction
- 📝 Payload/data inspection
- 💾 Option to log captured packets for later review

---

## Tech Stack

- **Language:** Python 3
- **Library:** [Scapy](https://scapy.net/) (packet manipulation & sniffing)
<br></br>
---

## Sample output:
```
[+] Sniffing started on interface: eth0
[+] Packet Captured: IP 192.168.1.5 -> 142.250.72.14 | Protocol: TCP
[+] Packet Captured: IP 192.168.1.5 -> 8.8.8.8 | Protocol: UDP
```
---

## About the Internship

This project was built as part of the **[CodeAlpha](https://www.codealpha.tech/) Cyber Security Internship Program**, focused on applying practical networking and security concepts.
