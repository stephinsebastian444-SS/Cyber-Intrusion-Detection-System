from collections import defaultdict
from datetime import datetime, timedelta


# ============================================================
# TRACKERS
# ============================================================

# Port scan tracker
# Stores:
# (destination_port, timestamp)
# for each source IP
port_scan_tracker = defaultdict(list)


# Brute-force tracker
# Stores:
# (destination_ip, destination_port, timestamp)
# for each source IP
brute_force_tracker = defaultdict(list)


# Last alert time
# Key:
# (source_ip, attack_type)
last_alert_time = {}


# ============================================================
# CONFIGURATION
# ============================================================

# -----------------------------
# Port Scan
# -----------------------------

PORT_SCAN_TIME_WINDOW = 5

PORT_THRESHOLD = 10


# -----------------------------
# Brute Force
# -----------------------------

BRUTE_FORCE_TIME_WINDOW = 10

BRUTE_FORCE_THRESHOLD = 15


# -----------------------------
# Alert Cooldown
# -----------------------------

ALERT_COOLDOWN = 30


# ============================================================
# HELPER FUNCTION
# ============================================================

def alert_allowed(source_ip, attack_type, current_time):
    """
    Prevent the same source IP from generating
    the same type of alert repeatedly.
    """

    key = (source_ip, attack_type)

    if key not in last_alert_time:
        return True

    return (
        current_time - last_alert_time[key]
        > timedelta(seconds=ALERT_COOLDOWN)
    )


def register_alert(source_ip, attack_type, current_time):
    """
    Record the time an alert was generated.
    """

    key = (source_ip, attack_type)

    last_alert_time[key] = current_time


# ============================================================
# MAIN DETECTION FUNCTION
# ============================================================

def detect_attack(packet_info):

    source_ip = packet_info["source_ip"]

    destination_ip = packet_info["destination_ip"]

    destination_port = packet_info["destination_port"]

    protocol = packet_info["protocol"]

    tcp_flags = packet_info.get("tcp_flags")


    current_time = datetime.now()


    # ========================================================
    # PORT SCAN DETECTION
    # ========================================================

    if destination_port is not None:

        # ----------------------------------------------------
        # Remove old entries
        # ----------------------------------------------------

        port_scan_tracker[source_ip] = [

            (port, timestamp)

            for port, timestamp
            in port_scan_tracker[source_ip]

            if current_time - timestamp
            <= timedelta(seconds=PORT_SCAN_TIME_WINDOW)

        ]


        # ----------------------------------------------------
        # Store current packet
        # ----------------------------------------------------

        port_scan_tracker[source_ip].append(
            (destination_port, current_time)
        )


        # ----------------------------------------------------
        # Count unique destination ports
        # ----------------------------------------------------

        unique_ports = {

            port

            for port, timestamp
            in port_scan_tracker[source_ip]

        }


        # ----------------------------------------------------
        # Detect Port Scan
        # ----------------------------------------------------

        if len(unique_ports) > PORT_THRESHOLD:

            if alert_allowed(
                source_ip,
                "Port Scan",
                current_time
            ):

                register_alert(
                    source_ip,
                    "Port Scan",
                    current_time
                )


                return {

                    "attack_type": "Port Scan",

                    "severity": "High",

                    "risk_score": 90,

                    "reason": (
                        f"{source_ip} contacted "
                        f"{len(unique_ports)} different "
                        f"destination ports within "
                        f"{PORT_SCAN_TIME_WINDOW} seconds."
                    ),

                    "recommendation": (
                        "Investigate or block this source IP."
                    )

                }


    # ========================================================
    # BRUTE-FORCE DETECTION
    # ========================================================

    # Only analyze TCP packets

    if protocol != "TCP":
        return None


    # --------------------------------------------------------
    # Only consider SYN packets
    #
    # SYN flag is normally represented by Scapy as:
    # "S"
    #
    # We specifically exclude established traffic such as:
    # ACK, PSH+ACK, FIN+ACK, etc.
    # --------------------------------------------------------

    if tcp_flags is None:
        return None


    tcp_flags = str(tcp_flags)


    if "S" not in tcp_flags:
        return None


    # Ignore packets that contain ACK as well.
    #
    # This prevents normal established TCP traffic
    # from being treated as connection attempts.
    if "A" in tcp_flags:
        return None


    # ========================================================
    # CLEAN OLD BRUTE-FORCE ENTRIES
    # ========================================================

    brute_force_tracker[source_ip] = [

        (
            tracked_destination_ip,
            tracked_destination_port,
            timestamp
        )

        for (
            tracked_destination_ip,
            tracked_destination_port,
            timestamp
        )
        in brute_force_tracker[source_ip]

        if current_time - timestamp
        <= timedelta(seconds=BRUTE_FORCE_TIME_WINDOW)

    ]


    # ========================================================
    # STORE CURRENT SYN ATTEMPT
    # ========================================================

    brute_force_tracker[source_ip].append(

        (
            destination_ip,
            destination_port,
            current_time
        )

    )


    # ========================================================
    # FIND CONNECTION ATTEMPTS TO THE SAME SERVICE
    # ========================================================

    same_service_attempts = [

        timestamp

        for (
            tracked_destination_ip,
            tracked_destination_port,
            timestamp
        )
        in brute_force_tracker[source_ip]

        if (
            tracked_destination_ip == destination_ip
            and
            tracked_destination_port == destination_port
        )

    ]


    attempt_count = len(same_service_attempts)


    # ========================================================
    # DETECT BRUTE FORCE
    # ========================================================

    if attempt_count >= BRUTE_FORCE_THRESHOLD:

        if alert_allowed(
            source_ip,
            "Brute Force",
            current_time
        ):

            register_alert(
                source_ip,
                "Brute Force",
                current_time
            )


            return {

                "attack_type": "Brute Force",

                "severity": "High",

                "risk_score": 85,

                "reason": (
                    f"{source_ip} generated "
                    f"{attempt_count} TCP SYN connection "
                    f"attempts to "
                    f"{destination_ip}:{destination_port} "
                    f"within "
                    f"{BRUTE_FORCE_TIME_WINDOW} seconds."
                ),

                "recommendation": (
                    "Investigate repeated connection "
                    "attempts to the targeted service "
                    "and consider blocking the source IP."
                )

            }


    # ========================================================
    # NO ATTACK
    # ========================================================

    return None