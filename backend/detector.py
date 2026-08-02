from collections import defaultdict
from datetime import datetime, timedelta

# Stores (destination_port, timestamp) for each source IP
port_scan_tracker = defaultdict(list)

# Stores the last time an alert was generated for each IP
last_alert_time = {}

# Configuration
TIME_WINDOW = 5          # seconds
PORT_THRESHOLD = 10      # unique ports
ALERT_COOLDOWN = 30      # seconds


def detect_attack(packet_info):

    source_ip = packet_info["source_ip"]
    destination_port = packet_info["destination_port"]

    # Ignore packets without a destination port
    if destination_port is None:
        return None

    current_time = datetime.now()

    # ----------------------------------------------------
    # Remove packets older than TIME_WINDOW seconds
    # ----------------------------------------------------
    port_scan_tracker[source_ip] = [
        (port, timestamp)
        for port, timestamp in port_scan_tracker[source_ip]
        if current_time - timestamp <= timedelta(seconds=TIME_WINDOW)
    ]

    # ----------------------------------------------------
    # Save current packet
    # ----------------------------------------------------
    port_scan_tracker[source_ip].append(
        (destination_port, current_time)
    )

    # ----------------------------------------------------
    # Count UNIQUE destination ports
    # ----------------------------------------------------
    unique_ports = {
        port
        for port, timestamp in port_scan_tracker[source_ip]
    }

    # ----------------------------------------------------
    # Detect Port Scan
    # ----------------------------------------------------
    if len(unique_ports) > PORT_THRESHOLD:

        # Check cooldown
        if (
            source_ip not in last_alert_time
            or current_time - last_alert_time[source_ip]
            > timedelta(seconds=ALERT_COOLDOWN)
        ):

            last_alert_time[source_ip] = current_time

            return {
                "attack_type": "Port Scan",
                "severity": "High",
                "risk_score": 90,
                "reason": (
                    f"{source_ip} contacted "
                    f"{len(unique_ports)} different ports "
                    f"within {TIME_WINDOW} seconds."
                ),
                "recommendation": (
                    "Investigate or block this source IP."
                )
            }

    return None