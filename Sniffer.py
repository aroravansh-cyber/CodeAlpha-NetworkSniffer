from scapy.all import sniff, IP, TCP, UDP, ICMP, IPv6, ARP, Raw

packet_count = 0
ip_version = "both"


def analyze_packet(packet):
    global packet_count
    packet_count += 1

    print("\n" + "=" * 120)
    print(f"Packet #{packet_count}")
    print("=" * 120)

    # ARP
    if ARP in packet:
        print("Type            : ARP")
        print(f"Source MAC      : {packet[ARP].hwsrc}")
        print(f"Destination MAC : {packet[ARP].hwdst}")
        print(f"Source IP       : {packet[ARP].psrc}")
        print(f"Destination IP  : {packet[ARP].pdst}")
        return

    # IPv4
    if IP in packet:
        print("Type            : IPv4")
        print(f"Source IP       : {packet[IP].src}")
        print(f"Destination IP  : {packet[IP].dst}")

        if TCP in packet:
            protocol = "TCP"
        elif UDP in packet:
            protocol = "UDP"
        elif ICMP in packet:
            protocol = "ICMP"
        else:
            protocol = "Other"

        print(f"Protocol        : {protocol}")

        if TCP in packet:
            print(f"Source Port     : {packet[TCP].sport}")
            print(f"Destination Port: {packet[TCP].dport}")

        elif UDP in packet:
            print(f"Source Port     : {packet[UDP].sport}")
            print(f"Destination Port: {packet[UDP].dport}")

        if Raw in packet:
            print(f"Payload         : {packet[Raw].load[:80]}")
        else:
            print("Payload         : No payload")

        return

    # IPv6
    if IPv6 in packet:
        print("Type            : IPv6")
        print(f"Source IP       : {packet[IPv6].src}")
        print(f"Destination IP  : {packet[IPv6].dst}")

        if TCP in packet:
            protocol = "TCP"
        elif UDP in packet:
            protocol = "UDP"
        else:
            protocol = "Other"

        print(f"Protocol        : {protocol}")

        if TCP in packet:
            print(f"Source Port     : {packet[TCP].sport}")
            print(f"Destination Port: {packet[TCP].dport}")

        elif UDP in packet:
            print(f"Source Port     : {packet[UDP].sport}")
            print(f"Destination Port: {packet[UDP].dport}")

        if Raw in packet:
            print(f"Payload         : {packet[Raw].load[:80]}")
        else:
            print("Payload         : No payload")

        return

    print("Type            : Other / Non-IP packet")


def get_ip_filter():
    if ip_version == "ipv4":
        return "ip"

    elif ip_version == "ipv6":
        return "ip6"

    return None


def start_sniffer(packet_limit):
    global packet_count

    packet_count = 0

    packet_filter = get_ip_filter()

    print("\n" + "=" * 120)
    print("[+] NETWORK SNIFFER STARTED")
    print("[!] NOTE: Please wait, packet capture may take some time.")
    print("=" * 120)

    if ip_version == "ipv4":
        print("[+] IP Version    : IPv4")
    elif ip_version == "ipv6":
        print("[+] IP Version    : IPv6")
    else:
        print("[+] IP Version    : IPv4 + IPv6")

    if packet_limit == 0:
        print("[+] Capture Mode   : Continuous")
    else:
        print(f"[+] Packet Limit   : {packet_limit}")

    print("[+] Press Ctrl+C to stop")
    print("=" * 120)

    try:
        sniff(
            prn=analyze_packet,
            count=packet_limit,
            filter=packet_filter,
            store=False
        )

    except KeyboardInterrupt:
        print("\n\n[!] Capture stopped by user.")

    except Exception as e:
        print(f"\n[-] Error: {e}")

    print(f"\nTotal packets captured: {packet_count}")

#ip version selection which is select by user mainly for ipv4, ipv6 or both
def select_ip_version():
    global ip_version

    while True:
        print("\n" + "=" * 120)
        print("                 IP VERSION")
        print("=" * 120)

        print("1. IPv4")
        print("2. IPv6")
        print("3. Both IPv4 & IPv6")
        print("=" * 120)

        choice = input("Enter your choice: ").strip()

        if choice == "1":
            ip_version = "ipv4"
            return True

        elif choice == "2":
            ip_version = "ipv6"
            return True

        elif choice == "3":
            ip_version = "both"
            return True

        else:
            print("\n[-] Invalid choice. Please select 1-3.")


def main():

    while True:

        print("\n" + "=" * 120)

        print("""
            ███╗   ██╗███████╗████████╗██╗    ██╗ ██████╗ ██████╗ ██╗  ██╗     ███████╗ ███╗   ██╗ ██╗ ███████╗ ███████╗ ███████╗ ██████╗
            ████╗  ██║██╔════╝╚══██╔══╝██║    ██║██╔═══██╗██╔══██╗██║ ██╔╝     ██╔════╝ ████╗  ██║ ██║ ██╔════╝ ██╔════╝ ██╔════╝ ██╔══██╗
            ██╔██╗ ██║█████╗     ██║   ██║ █╗ ██║██║   ██║██████╔╝█████╔╝      ███████╗ ██╔██╗ ██║ ██║ █████╗   █████╗   █████╗   ██████╔╝
            ██║╚██╗██║██╔══╝     ██║   ██║███╗██║██║   ██║██╔══██╗██╔═██╗      ╚════██║ ██║╚██╗██║ ██║ ██╔══╝   ██╔══╝   ██╔══╝   ██╔══██╗
            ██║ ╚████║███████╗   ██║   ╚███╔███╔╝╚██████╔╝██║  ██║██║  ██╗     ███████║ ██║ ╚████║ ██║ ██║      ██║      ███████╗ ██║  ██║
            ╚═╝  ╚═══╝╚══════╝   ╚═╝    ╚══╝╚══╝  ╚═════╝ ╚═╝  ╚═╝╚═╝  ╚═╝     ╚══════╝ ╚═╝  ╚═══╝ ╚═╝ ╚═╝      ╚═╝      ╚══════╝ ╚═╝  ╚═╝
        """)

        print("=" * 120)
        print("              NETWORK SNIFFER")
        print("=" * 120)

        print("\nSelect Packet Capture Mode:")
        print("1. Capture 10 packets")
        print("2. Capture 20 packets")
        print("3. Capture 50 packets")
        print("4. Capture packets continuously")
        print("5. Exit")

        print("=" * 120)

        choice = input("Enter your choice: ").strip()

        if choice == "1":
            packet_limit = 10

        elif choice == "2":
            packet_limit = 20

        elif choice == "3":
            packet_limit = 50

        elif choice == "4":
            packet_limit = 0

        elif choice == "5":
            print("\nExiting Network Sniffer...")
            break

        else:
            print("\n[-] Invalid choice. Please select 1-5.")
            continue

        # Select IPv4 / IPv6 / Both
        select_ip_version()

        # Start capture
        start_sniffer(packet_limit)


if __name__ == "__main__":
    main()