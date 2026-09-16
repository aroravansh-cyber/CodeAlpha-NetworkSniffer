from scapy.all import sniff, IP, TCP, UDP, ICMP, Raw


packet_count = 0


def analyze_packet(packet):
    global packet_count
    packet_count += 1

    print("\n" + "=" * 60)
    print(f"Packet #{packet_count}")
    print("=" * 60)

    if IP not in packet:
        print("Type           : Non-IP packet")
        return

    print(f"Source IP      : {packet[IP].src}")
    print(f"Destination IP : {packet[IP].dst}")

    if TCP in packet:
        protocol = "TCP"
    elif UDP in packet:
        protocol = "UDP"
    elif ICMP in packet:
        protocol = "ICMP"
    else:
        protocol = "Other"

    print(f"Protocol       : {protocol}")

    if TCP in packet:
        print(f"Source Port    : {packet[TCP].sport}")
        print(f"Destination Port: {packet[TCP].dport}")

    elif UDP in packet:
        print(f"Source Port    : {packet[UDP].sport}")
        print(f"Destination Port: {packet[UDP].dport}")

    if Raw in packet:
        payload = packet[Raw].load
        print(f"Payload        : {payload[:80]}")
    else:
        print("Payload        : No payload")


def start_sniffer(packet_limit):
    global packet_count
    packet_count = 0

    print("\n[+] Network Sniffer Started")
    print("[+] Press Ctrl+C to stop\n")

    try:
        sniff(
            prn=analyze_packet,
            count=packet_limit,
            store=False
        )
    except KeyboardInterrupt:
        print("\n\n[!] Capture stopped by user.")

    print(f"\nTotal packets captured: {packet_count}")


def main():
    while True:
        print("\n" + "=" * 50)
        print("""
        ███╗   ██╗███████╗████████╗██╗    ██╗ ██████╗ ██████╗ ██╗  ██╗     ███████╗ ███╗   ██╗ ██╗ ███████╗ ███████╗ ███████╗ ██████╗ 
        ████╗  ██║██╔════╝╚══██╔══╝██║    ██║██╔═══██╗██╔══██╗██║ ██╔╝     ██╔════╝ ████╗  ██║ ██║ ██╔════╝ ██╔════╝ ██╔════╝ ██╔══██╗
        ██╔██╗ ██║█████╗     ██║   ██║ █╗ ██║██║   ██║██████╔╝█████╔╝      ███████╗ ██╔██╗ ██║ ██║ █████╗   █████╗   █████╗   ██████╔╝
        ██║╚██╗██║██╔══╝     ██║   ██║███╗██║██║   ██║██╔══██╗██╔═██╗      ╚════██║ ██║╚██╗██║ ██║ ██╔══╝   ██╔══╝   ██╔══╝   ██╔══██╗
        ██║ ╚████║███████╗   ██║   ╚███╔███╔╝╚██████╔╝██║  ██║██║  ██╗     ███████║ ██║ ╚████║ ██║ ██║      ██║      ███████╗ ██║  ██║
        ╚═╝  ╚═══╝╚══════╝   ╚═╝    ╚══╝╚══╝  ╚═════╝ ╚═╝  ╚═╝╚═╝  ╚═╝     ╚══════╝ ╚═╝  ╚═══╝ ╚═╝ ╚═╝      ╚═╝      ╚══════╝ ╚═╝  ╚═╝

        
        """)
        print("=" * 50)
        print("1. Capture 10 packets")
        print("2. Capture 25 packets")
        print("3. Capture 50 packets")
        print("4. Capture packets continuously")
        print("5. Exit")
        print("=" * 50)

        choice = input("Enter your choice: ").strip()

        if choice == "1":
            start_sniffer(10)

        elif choice == "2":
            start_sniffer(25)

        elif choice == "3":
            start_sniffer(50)

        elif choice == "4":
            start_sniffer(0)

        elif choice == "5":
            print("\nExiting Network Sniffer...")
            break

        else:
            print("\n[-] Invalid choice. Please select 1-5.")


if __name__ == "__main__":
    main()