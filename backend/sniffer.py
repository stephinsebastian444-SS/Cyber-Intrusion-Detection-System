from scapy.all import sniff, IP, TCP, UDP, ICMP

import detector
import crud
import schemas

from database import SessionLocal


# ============================================================
# PACKET PROCESSING
# ============================================================

def process_packet(packet):

    # --------------------------------------------------------
    # Ignore packets without an IP layer
    # --------------------------------------------------------

    if not packet.haslayer(IP):
        return


    # --------------------------------------------------------
    # Default values
    # --------------------------------------------------------

    protocol = "Other"

    source_port = None
    destination_port = None

    tcp_flags = None


    # --------------------------------------------------------
    # TCP PACKET
    # --------------------------------------------------------

    if packet.haslayer(TCP):

        protocol = "TCP"

        source_port = packet[TCP].sport

        destination_port = packet[TCP].dport

        tcp_flags = str(packet[TCP].flags)


    # --------------------------------------------------------
    # UDP PACKET
    # --------------------------------------------------------

    elif packet.haslayer(UDP):

        protocol = "UDP"

        source_port = packet[UDP].sport

        destination_port = packet[UDP].dport


    # --------------------------------------------------------
    # ICMP PACKET
    # --------------------------------------------------------

    elif packet.haslayer(ICMP):

        protocol = "ICMP"


    # ========================================================
    # CREATE PACKET INFORMATION
    # ========================================================

    packet_info = {

        "source_ip": packet[IP].src,

        "destination_ip": packet[IP].dst,

        "protocol": protocol,

        "source_port": source_port,

        "destination_port": destination_port,

        "packet_size": len(packet),

        # Used by detector.py
        # Not stored in packets table
        "tcp_flags": tcp_flags

    }


    # ========================================================
    # IGNORE MULTICAST / DISCOVERY TRAFFIC
    # ========================================================

    if destination_port in [1900, 5353, 67, 68]:

        return


    # ========================================================
    # IGNORE ROUTER TRAFFIC
    # ========================================================

    if packet_info["source_ip"] == "192.168.0.1":

        return


    # ========================================================
    # DISPLAY PACKET
    # ========================================================

    print(
        f"{packet_info['source_ip']} -> "
        f"{packet_info['destination_ip']} | "
        f"{protocol} | "
        f"Port: {destination_port} | "
        f"Flags: {tcp_flags}"
    )


    # ========================================================
    # SPECIAL KALI MESSAGE
    # ========================================================

    if packet_info["source_ip"] == "192.168.0.208":

        print(
            "<<<<<<<<<<<< KALI PACKET >>>>>>>>>>>"
        )


    # Display complete packet information
    print(packet_info)


    # ========================================================
    # SAVE PACKET TO DATABASE
    # ========================================================

    db = SessionLocal()

    try:

        # ----------------------------------------------------
        # Only save fields that exist in Packet model
        # ----------------------------------------------------

        packet_data = {

            "source_ip": packet_info["source_ip"],

            "destination_ip": packet_info["destination_ip"],

            "protocol": packet_info["protocol"],

            "source_port": packet_info["source_port"],

            "destination_port": packet_info["destination_port"],

            "packet_size": packet_info["packet_size"]

        }


        crud.create_packet(

            db=db,

            packet_data=packet_data

        )


        print(
            "Packet saved to database."
        )


    except Exception as e:

        print(
            "Packet Database Error:",
            e
        )


    finally:

        db.close()


    # ========================================================
    # DETECT ATTACK
    # ========================================================

    try:

        alert = detector.detect_attack(
            packet_info
        )


    except Exception as e:

        print(
            "Detector Error:",
            e
        )

        return


    # ========================================================
    # SAVE ALERT IF DETECTED
    # ========================================================

    if alert:

        print()
        print("==============================")

        print(
            "Suspicious Packet Detected!"
        )

        print(alert)

        print("==============================")
        print()


        db = SessionLocal()

        try:

            # ------------------------------------------------
            # Create Alert schema
            # ------------------------------------------------

            alert_data = schemas.AlertCreate(

                source_ip=packet_info["source_ip"],

                attack_type=alert["attack_type"],

                severity=alert["severity"],

                risk_score=alert["risk_score"],

                reason=alert["reason"],

                recommendation=alert["recommendation"]

            )


            # ------------------------------------------------
            # Save alert
            # ------------------------------------------------

            crud.create_alert(

                db=db,

                alert=alert_data

            )


            print(
                "Alert saved to database."
            )


        except Exception as e:

            print(
                "Alert Database Error:",
                e
            )


        finally:

            db.close()


# ============================================================
# START PACKET SNIFFER
# ============================================================

def start_sniffer():

    print(
        "==================================="
    )

    print(
        "Packet Sniffer Started..."
    )

    print(
        "Press CTRL+C to Stop"
    )

    print(
        "==================================="
    )


    sniff(

        iface=r"\Device\NPF_{5475494F-4E6E-4762-A913-E2CA4B01E0EB}",

        prn=process_packet,

        store=False

    )


# ============================================================
# RUN ONLY WHEN EXECUTED DIRECTLY
# ============================================================

if __name__ == "__main__":

    start_sniffer()