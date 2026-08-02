from scapy.all import sniff, IP, TCP, UDP

import detector
import crud
import schemas

from database import SessionLocal


def process_packet(packet):

    if not packet.haslayer(IP):
        return

    protocol = "Other"
    sport = None
    dport = None
    tcp_flags = None

    # -----------------------------
    # TCP Packet
    # -----------------------------
    if packet.haslayer(TCP):
        protocol = "TCP"
        sport = packet[TCP].sport
        dport = packet[TCP].dport
        tcp_flags = str(packet[TCP].flags)

    # -----------------------------
    # UDP Packet
    # -----------------------------
    elif packet.haslayer(UDP):
        protocol = "UDP"
        sport = packet[UDP].sport
        dport = packet[UDP].dport

    packet_info = {
        "source_ip": packet[IP].src,
        "destination_ip": packet[IP].dst,
        "protocol": protocol,
        "source_port": sport,
        "destination_port": dport,
        "packet_size": len(packet),
        "tcp_flags": tcp_flags
    }

    # -----------------------------
    # Save Packet to Database
    # -----------------------------
    db = SessionLocal()

    try:

        crud.create_packet(
            db=db,
            packet_data={
                "source_ip": packet_info["source_ip"],
                "destination_ip": packet_info["destination_ip"],
                "protocol": packet_info["protocol"],
                "source_port": packet_info["source_port"],
                "destination_port": packet_info["destination_port"],
                "packet_size": packet_info["packet_size"]
            }
        )

    except Exception as e:

        print("Packet Save Error:", e)

    finally:

        db.close()

    # -----------------------------
    # Ignore multicast / discovery traffic
    # -----------------------------
    if dport in [1900, 5353, 67, 68]:
        return

    # Ignore router traffic
    if packet_info["source_ip"] == "192.168.0.1":
        return

    # -----------------------------
    # Print every packet
    # -----------------------------
    print(
        f"{packet_info['source_ip']} -> "
        f"{packet_info['destination_ip']} | "
        f"{protocol} | "
        f"Port: {dport} | "
        f"Flags: {tcp_flags}"
    )

    # -----------------------------
    # Detect attack
    # -----------------------------
    if packet_info["source_ip"] == "192.168.0.208":
        print("<<<<<<<<<<<< KALI PACKET >>>>>>>>>>>")
    
    print(packet_info)
    alert = detector.detect_attack(packet_info)

    if alert:

        print("\n==============================")
        print("Suspicious Packet Detected!")
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

            print("Alert saved to database.")

        except Exception as e:

            print("Database Error:", e)

        finally:

            db.close()


print("===================================")
print("Packet Sniffer Started...")
print("Press CTRL+C to Stop")
print("===================================")

sniff(
    iface=r"\Device\NPF_{5475494F-4E6E-4762-A913-E2CA4B01E0EB}",
    prn=process_packet,
    store=False
)