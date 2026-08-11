from scapy.all import sniff, IP, TCP, UDP

import detector
import crud
import schemas

from database import SessionLocal


# ============================================================
# Packet Processing
# ============================================================

def process_packet(packet):

    # --------------------------------------------------------
    # Ignore packets that do not contain an IP layer
    # --------------------------------------------------------

    if not packet.haslayer(IP):
        return


    # --------------------------------------------------------
    # Default packet values
    # --------------------------------------------------------

    protocol = "Other"

    source_port = None
    destination_port = None

    tcp_flags = None


    # --------------------------------------------------------
    # TCP Packet
    # --------------------------------------------------------

    if packet.haslayer(TCP):

        protocol = "TCP"

        source_port = packet[TCP].sport

        destination_port = packet[TCP].dport

        tcp_flags = str(packet[TCP].flags)


    # --------------------------------------------------------
    # UDP Packet
    # --------------------------------------------------------

    elif packet.haslayer(UDP):

        protocol = "UDP"

        source_port = packet[UDP].sport

        destination_port = packet[UDP].dport


    # --------------------------------------------------------
    # Create packet information
    #
    # IMPORTANT:
    # tcp_flags is NOT included here because the
    # Packet database model does not have a tcp_flags column.
    # --------------------------------------------------------

    packet_info = {

        "source_ip": packet[IP].src,

        "destination_ip": packet[IP].dst,

        "protocol": protocol,

        "source_port": source_port,

        "destination_port": destination_port,

        "packet_size": len(packet)

    }


    # --------------------------------------------------------
    # Ignore multicast / discovery traffic
    # --------------------------------------------------------

    if destination_port in [1900, 5353, 67, 68]:

        return


    # --------------------------------------------------------
    # Ignore router traffic
    # --------------------------------------------------------

    if packet_info["source_ip"] == "192.168.0.1":

        return


    # --------------------------------------------------------
    # Print packet information
    # --------------------------------------------------------

    print(
        f"{packet_info['source_ip']} -> "
        f"{packet_info['destination_ip']} | "
        f"{protocol} | "
        f"Port: {destination_port} | "
        f"Flags: {tcp_flags}"
    )


    # --------------------------------------------------------
    # Special Kali detection message
    # --------------------------------------------------------

    if packet_info["source_ip"] == "192.168.0.208":

        print(
            "<<<<<<<<<<<< KALI PACKET >>>>>>>>>>>"
        )


    print(packet_info)


    # ========================================================
    # SAVE PACKET TO DATABASE
    # ========================================================

    db = SessionLocal()

    try:

        crud.create_packet(
            db=db,
            packet_data=packet_info
        )

        print("Packet saved to database.")

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

    alert = detector.detect_attack(packet_info)


    # ========================================================
    # SAVE ALERT IF ATTACK DETECTED
    # ========================================================

    if alert:

        print("\n==============================")

        print(
            "Suspicious Packet Detected!"
        )

        print(alert)

        print("==============================\n")


        db = SessionLocal()

        try:

            alert_data = schemas.AlertCreate(

                source_ip=packet_info["source_ip"],

                attack_type=alert["attack_type"],

                severity=alert["severity"],

                risk_score=alert["risk_score"],

                reason=alert["reason"],

                recommendation=alert["recommendation"]

            )


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