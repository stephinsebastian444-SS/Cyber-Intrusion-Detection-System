from collections import defaultdict
from datetime import datetime, timedelta


# ============================================================
# TRACKERS
# ============================================================

# ------------------------------------------------------------
# Port Scan Tracker
#
# Stores:
# (destination_port, timestamp)
#
# Key:
# source IP
# ------------------------------------------------------------

port_scan_tracker = defaultdict(list)


# ------------------------------------------------------------
# Brute Force Tracker
#
# Stores:
# (destination_ip, destination_port, timestamp)
#
# Key:
# source IP
# ------------------------------------------------------------

brute_force_tracker = defaultdict(list)


# ------------------------------------------------------------
# SYN Flood Tracker
#
# Stores:
# (destination_ip, destination_port, timestamp)
#
# Key:
# source IP
# ------------------------------------------------------------

syn_flood_tracker = defaultdict(list)


# ------------------------------------------------------------
# ICMP Flood Tracker
#
# Stores:
# timestamp
#
# Key:
# source IP
# ------------------------------------------------------------

icmp_flood_tracker = defaultdict(list)


# ------------------------------------------------------------
# Last Alert Time
#
# Key:
# (source_ip, attack_type)
# ------------------------------------------------------------

last_alert_time = {}


# ============================================================
# CONFIGURATION
# ============================================================

# ------------------------------------------------------------
# Port Scan
# ------------------------------------------------------------

PORT_SCAN_TIME_WINDOW = 5

PORT_THRESHOLD = 10


# ------------------------------------------------------------
# Brute Force
# ------------------------------------------------------------

BRUTE_FORCE_TIME_WINDOW = 10

BRUTE_FORCE_THRESHOLD = 15


# ------------------------------------------------------------
# SYN Flood
# ------------------------------------------------------------

SYN_FLOOD_TIME_WINDOW = 5

SYN_FLOOD_THRESHOLD = 30


# ------------------------------------------------------------
# ICMP Flood
# ------------------------------------------------------------

ICMP_FLOOD_TIME_WINDOW = 5

ICMP_FLOOD_THRESHOLD = 50


# ------------------------------------------------------------
# Alert Cooldown
# ------------------------------------------------------------

ALERT_COOLDOWN = 30


# ============================================================
# SUSPICIOUS SERVICES
# ============================================================

# These ports are not automatically attacks.
# They represent services that may deserve investigation.

SUSPICIOUS_SERVICES = {

    21: {
        "attack_type": "Suspicious FTP Activity",
        "severity": "Medium",
        "risk_score": 50,
        "service": "FTP"
    },

    23: {
        "attack_type": "Suspicious Telnet Activity",
        "severity": "High",
        "risk_score": 70,
        "service": "Telnet"
    },

    445: {
        "attack_type": "Suspicious SMB Activity",
        "severity": "Medium",
        "risk_score": 60,
        "service": "SMB"
    },

    3389: {
        "attack_type": "Suspicious RDP Activity",
        "severity": "High",
        "risk_score": 75,
        "service": "RDP"
    }

}


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


# ============================================================
# REGISTER ALERT
# ============================================================

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

    # --------------------------------------------------------
    # Extract packet information
    # --------------------------------------------------------

    source_ip = packet_info["source_ip"]

    destination_ip = packet_info["destination_ip"]

    destination_port = packet_info["destination_port"]

    protocol = packet_info["protocol"]

    tcp_flags = packet_info.get("tcp_flags")

    packet_size = packet_info.get("packet_size", 0)

    current_time = datetime.now()


    # ========================================================
    # RULE 1 - PORT SCAN
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
        # Store current destination port
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
                        "Investigate the source IP and "
                        "consider blocking it if the "
                        "activity is unauthorized."
                    )

                }


    # ========================================================
    # RULE 2 - SUSPICIOUS SERVICE ACTIVITY
    # ========================================================

    if (
        protocol == "TCP"
        and
        destination_port in SUSPICIOUS_SERVICES
    ):

        service_info = SUSPICIOUS_SERVICES[destination_port]

        attack_type = service_info["attack_type"]

        if alert_allowed(
            source_ip,
            attack_type,
            current_time
        ):

            register_alert(
                source_ip,
                attack_type,
                current_time
            )

            return {

                "attack_type": attack_type,

                "severity": service_info["severity"],

                "risk_score": service_info["risk_score"],

                "reason": (
                    f"{source_ip} connected to "
                    f"{service_info['service']} service "
                    f"on "
                    f"{destination_ip}:"
                    f"{destination_port}."
                ),

                "recommendation": (
                    f"Verify whether {service_info['service']} "
                    "access is authorized. Investigate "
                    "unexpected external access."
                )

            }


    # ========================================================
    # RULE 3 - TCP ANALYSIS
    # ========================================================

    if protocol != "TCP":

        # ICMP rules are checked later.

        # Non-TCP packets do not continue
        # into TCP-specific rules.

        if protocol != "ICMP":
            return None

    # ========================================================
    # TCP FLAG VALIDATION
    # ========================================================

    if protocol == "TCP":

        if tcp_flags is None:

            return None

        tcp_flags = str(tcp_flags)


        # ----------------------------------------------------
        # Only analyze SYN packets for SYN-based rules
        # ----------------------------------------------------

        if "S" in tcp_flags and "A" not in tcp_flags:


            # =================================================
            # RULE 4 - SYN FLOOD
            # =================================================

            # -------------------------------------------------
            # Remove old SYN entries
            # -------------------------------------------------

            syn_flood_tracker[source_ip] = [

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
                in syn_flood_tracker[source_ip]

                if current_time - timestamp
                <= timedelta(seconds=SYN_FLOOD_TIME_WINDOW)

            ]


            # -------------------------------------------------
            # Store current SYN attempt
            # -------------------------------------------------

            syn_flood_tracker[source_ip].append(

                (
                    destination_ip,
                    destination_port,
                    current_time
                )

            )


            # -------------------------------------------------
            # Count SYN packets
            # -------------------------------------------------

            syn_count = len(
                syn_flood_tracker[source_ip]
            )


            # -------------------------------------------------
            # Detect SYN Flood
            # -------------------------------------------------

            if syn_count >= SYN_FLOOD_THRESHOLD:

                if alert_allowed(
                    source_ip,
                    "SYN Flood",
                    current_time
                ):

                    register_alert(
                        source_ip,
                        "SYN Flood",
                        current_time
                    )

                    return {

                        "attack_type": "SYN Flood",

                        "severity": "Critical",

                        "risk_score": 95,

                        "reason": (
                            f"{source_ip} generated "
                            f"{syn_count} TCP SYN packets "
                            f"within "
                            f"{SYN_FLOOD_TIME_WINDOW} seconds."
                        ),

                        "recommendation": (
                            "Investigate the source immediately "
                            "and consider rate limiting or "
                            "blocking the source IP."
                        )

                    }


            # =================================================
            # RULE 5 - BRUTE FORCE
            # =================================================

            # -------------------------------------------------
            # Remove old brute-force entries
            # -------------------------------------------------

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


            # -------------------------------------------------
            # Store current SYN attempt
            # -------------------------------------------------

            brute_force_tracker[source_ip].append(

                (
                    destination_ip,
                    destination_port,
                    current_time
                )

            )


            # -------------------------------------------------
            # Find attempts to same service
            # -------------------------------------------------

            same_service_attempts = [

                timestamp

                for (
                    tracked_destination_ip,
                    tracked_destination_port,
                    timestamp
                )
                in brute_force_tracker[source_ip]

                if (
                    tracked_destination_ip
                    == destination_ip
                    and
                    tracked_destination_port
                    == destination_port
                )

            ]


            attempt_count = len(
                same_service_attempts
            )


            # -------------------------------------------------
            # Detect Brute Force
            # -------------------------------------------------

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
                            f"{attempt_count} TCP SYN "
                            f"connection attempts to "
                            f"{destination_ip}:"
                            f"{destination_port} within "
                            f"{BRUTE_FORCE_TIME_WINDOW} seconds."
                        ),

                        "recommendation": (
                            "Investigate repeated connection "
                            "attempts and consider blocking "
                            "or rate limiting the source IP."
                        )

                    }


    # ========================================================
    # RULE 6 - ICMP FLOOD
    # ========================================================

    if protocol == "ICMP":

        # ----------------------------------------------------
        # Remove old ICMP entries
        # ----------------------------------------------------

        icmp_flood_tracker[source_ip] = [

            timestamp

            for timestamp
            in icmp_flood_tracker[source_ip]

            if current_time - timestamp
            <= timedelta(seconds=ICMP_FLOOD_TIME_WINDOW)

        ]


        # ----------------------------------------------------
        # Store current ICMP packet
        # ----------------------------------------------------

        icmp_flood_tracker[source_ip].append(
            current_time
        )


        # ----------------------------------------------------
        # Count ICMP packets
        # ----------------------------------------------------

        icmp_count = len(
            icmp_flood_tracker[source_ip]
        )


        # ----------------------------------------------------
        # Detect ICMP Flood
        # ----------------------------------------------------

        if icmp_count >= ICMP_FLOOD_THRESHOLD:

            if alert_allowed(
                source_ip,
                "ICMP Flood",
                current_time
            ):

                register_alert(
                    source_ip,
                    "ICMP Flood",
                    current_time
                )

                return {

                    "attack_type": "ICMP Flood",

                    "severity": "High",

                    "risk_score": 90,

                    "reason": (
                        f"{source_ip} generated "
                        f"{icmp_count} ICMP packets "
                        f"within "
                        f"{ICMP_FLOOD_TIME_WINDOW} seconds."
                    ),

                    "recommendation": (
                        "Investigate the source IP and "
                        "consider ICMP rate limiting or "
                        "blocking excessive traffic."
                    )

                }
    # ========================================================
    # NO ATTACK DETECTED
    # ========================================================

    return None