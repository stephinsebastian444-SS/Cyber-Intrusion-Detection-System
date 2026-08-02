from scapy.all import sniff

print("Listening for ICMP...")

sniff(
    filter="icmp",
    store=False,
    prn=lambda p: p.summary()
)