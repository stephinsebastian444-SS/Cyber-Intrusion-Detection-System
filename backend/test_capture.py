from detector import detect_attack


def make_packet(
    source_ip,
    destination_ip,
    destination_port,
    protocol="TCP",
    tcp_flags="S"
):
    return {
        "source_ip": source_ip,
        "destination_ip": destination_ip,
        "protocol": protocol,
        "source_port": 50000,
        "destination_port": destination_port,
        "packet_size": 100,
        "tcp_flags": tcp_flags
    }


print("===================================")
print("CyberShield IDS Detector Test")
print("===================================")


# ============================================================
# TEST 1 - NORMAL TCP TRAFFIC
# ============================================================

print("\n[TEST 1] Normal TCP traffic")

packet = make_packet(
    source_ip="10.0.0.10",
    destination_ip="10.0.0.20",
    destination_port=443,
    tcp_flags="A"
)

result = detect_attack(packet)

if result is None:

    print("PASS - No alert generated.")

else:

    print("FAIL - Unexpected alert:")
    print(result)


# ============================================================
# TEST 2 - PORT SCAN
# ============================================================

print("\n[TEST 2] Port Scan")

port_scan_result = None

for port in range(1, 13):

    packet = make_packet(
        source_ip="10.0.0.50",
        destination_ip="10.0.0.20",
        destination_port=port,
        tcp_flags="S"
    )

    result = detect_attack(packet)

    if result is not None:

        port_scan_result = result


if (
    port_scan_result is not None
    and port_scan_result["attack_type"] == "Port Scan"
):

    print("PASS - Port Scan detected.")
    print(port_scan_result)

else:

    print("FAIL - Port Scan was not detected.")


# ============================================================
# TEST 3 - BRUTE FORCE
# ============================================================

print("\n[TEST 3] Repeated SYN attempts")

brute_force_result = None

for i in range(20):

    packet = make_packet(
        source_ip="10.0.0.60",
        destination_ip="10.0.0.20",
        destination_port=22,
        tcp_flags="S"
    )

    result = detect_attack(packet)

    if result is not None:

        brute_force_result = result


if (
    brute_force_result is not None
    and brute_force_result["attack_type"] == "Brute Force"
):

    print("PASS - Brute Force detected.")
    print(brute_force_result)

else:

    print("FAIL - Brute Force was not detected.")


print("\n===================================")
print("Detector tests completed.")
print("===================================")