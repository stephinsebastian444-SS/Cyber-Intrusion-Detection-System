import detector


print("===================================")
print("CYBER IDS DETECTOR TEST")
print("===================================")


# ============================================================
# PORT SCAN TEST
# ============================================================

print("\nTesting Port Scan...")

for port in range(1, 13):

    packet = {
        "source_ip": "10.10.10.50",
        "destination_ip": "10.10.10.100",
        "protocol": "TCP",
        "source_port": 50000 + port,
        "destination_port": port,
        "packet_size": 100,
        "tcp_flags": "S"
    }

    alert = detector.detect_attack(packet)

    if alert:

        print("\nPORT SCAN ALERT:")
        print(alert)


# ============================================================
# BRUTE FORCE TEST
# ============================================================

print("\nTesting Brute Force...")

for attempt in range(16):

    packet = {
        "source_ip": "10.10.10.60",
        "destination_ip": "10.10.10.100",
        "protocol": "TCP",
        "source_port": 51000 + attempt,
        "destination_port": 22,
        "packet_size": 100,
        "tcp_flags": "S"
    }

    alert = detector.detect_attack(packet)

    if alert:

        print("\nBRUTE FORCE ALERT:")
        print(alert)


# ============================================================
# SYN FLOOD TEST
# ============================================================

print("\nTesting SYN Flood...")

for attempt in range(31):

    packet = {
        "source_ip": "10.10.10.70",
        "destination_ip": "10.10.10.100",
        "protocol": "TCP",
        "source_port": 52000 + attempt,
        "destination_port": 80,
        "packet_size": 100,
        "tcp_flags": "S"
    }

    alert = detector.detect_attack(packet)

    if alert:

        print("\nSYN FLOOD ALERT:")
        print(alert)


# ============================================================
# ICMP FLOOD TEST
# ============================================================

print("\nTesting ICMP Flood...")

for attempt in range(51):

    packet = {
        "source_ip": "10.10.10.80",
        "destination_ip": "10.10.10.100",
        "protocol": "ICMP",
        "source_port": None,
        "destination_port": None,
        "packet_size": 100,
        "tcp_flags": None
    }

    alert = detector.detect_attack(packet)

    if alert:

        print("\nICMP FLOOD ALERT:")
        print(alert)


print("\n===================================")
print("DETECTOR TEST COMPLETED")
print("===================================")