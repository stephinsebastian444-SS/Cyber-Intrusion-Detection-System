from scapy.all import IP, TCP

from sniffer import process_packet


print("===================================")
print("CYBER IDS FULL PIPELINE TEST")
print("===================================")

TEST_SOURCE_IP = "10.10.10.50"
TEST_DESTINATION_IP = "10.10.10.100"


# ============================================================
# GENERATE CONTROLLED PORT SCAN PATTERN
# ============================================================

print()
print("Generating controlled test packets...")
print()


for port in range(1, 12):

    packet = (
        IP(
            src=TEST_SOURCE_IP,
            dst=TEST_DESTINATION_IP
        )
        /
        TCP(
            sport=40000 + port,
            dport=port,
            flags="S"
        )
    )

    process_packet(packet)


print()
print("===================================")
print("FULL PIPELINE TEST COMPLETED")
print("===================================")
