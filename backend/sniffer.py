from scapy.all import sniff, IP, TCP, UDP
def process_packet(packet):

    if packet.haslayer(IP):

        print("--------------------------------")

        print("Source IP:", packet[IP].src)

        print("Destination IP:", packet[IP].dst)

        print("Packet Size:", len(packet))

        if packet.haslayer(TCP):
            print("Protocol: TCP")
            print("Source Port:", packet[TCP].sport)
            print("Destination Port:", packet[TCP].dport)

        elif packet.haslayer(UDP):
            print("Protocol: UDP")
            print("Source Port:", packet[UDP].sport)
            print("Destination Port:", packet[UDP].dport)

        else:
            print("Protocol: Other")
print("Packet Sniffer Started...")

sniff(prn=process_packet, store=False)
