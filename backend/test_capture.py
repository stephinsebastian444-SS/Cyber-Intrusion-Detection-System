import argparse
from datetime import datetime

import detector


EXPECTED_DETAILS = {
    "Port Scan": ("High", 90),
    "Brute Force": ("High", 85),
    "SYN Flood": ("Critical", 95),
    "ICMP Flood": ("High", 90),
    "Suspicious FTP Activity": ("Medium", 50),
    "Suspicious Telnet Activity": ("High", 70),
    "Suspicious SMB Activity": ("Medium", 60),
    "Suspicious RDP Activity": ("High", 75),
}


def reset_detector_state():
    """Clear module-level trackers so each test is independent."""
    detector.port_scan_tracker.clear()
    detector.brute_force_tracker.clear()
    detector.syn_flood_tracker.clear()
    detector.icmp_flood_tracker.clear()
    detector.last_alert_time.clear()


def make_packet(
    source_ip,
    destination_ip="10.10.10.100",
    protocol="TCP",
    source_port=None,
    destination_port=None,
    packet_size=100,
    tcp_flags=None,
):
    """Build the packet-info dictionary expected by detector.py."""
    return {
        "source_ip": source_ip,
        "destination_ip": destination_ip,
        "protocol": protocol,
        "source_port": source_port,
        "destination_port": destination_port,
        "packet_size": packet_size,
        "tcp_flags": tcp_flags,
    }


def run_case(name, packets, expected_attack_types):
    """Run one synthetic scenario and assert the detector's returned alerts."""
    reset_detector_state()
    events = []

    for packet_info in packets:
        alert = detector.detect_attack(packet_info)
        if alert is not None:
            events.append(
                {
                    "packet": packet_info,
                    "alert": alert,
                    "observed_at": datetime.now().astimezone().isoformat(
                        timespec="seconds"
                    ),
                }
            )

    expected = set(expected_attack_types)
    detected = {event["alert"]["attack_type"] for event in events}
    type_check_passed = detected == expected

    details_check_passed = all(
        (
            event["alert"].get("severity"),
            event["alert"].get("risk_score"),
        )
        == EXPECTED_DETAILS.get(event["alert"].get("attack_type"), (None, None))
        for event in events
    )

    passed = type_check_passed and details_check_passed

    print("\n" + "-" * 68)
    print(f"TEST: {name}")
    print(f"Synthetic packet records supplied: {len(packets)}")
    print("Expected alerts:", ", ".join(sorted(expected)) if expected else "None")
    print("Detected alerts:", ", ".join(sorted(detected)) if detected else "None")

    for event in events:
        alert = event["alert"]
        print(f"\n  Observed at: {event['observed_at']}")
        print(f"  Source IP:   {event['packet']['source_ip']}")
        print(f"  Attack type: {alert['attack_type']}")
        print(f"  Severity:    {alert['severity']}")
        print(f"  Risk score:  {alert['risk_score']}")
        print(f"  Reason:      {alert['reason']}")

    print("Result:", "PASS" if passed else "FAIL")
    if not type_check_passed:
        print(f"  Type mismatch. Expected {expected!r}; got {detected!r}.")
    if not details_check_passed:
        print("  At least one alert had an unexpected severity or risk score.")

    return {"name": name, "passed": passed, "events": events}


def build_test_cases():
    """Build safe, synthetic inputs for each implemented rule."""
    cases = []

    # Negative control: one ordinary-looking ACK packet should not trigger a rule.
    cases.append(
        (
            "Normal TCP ACK (negative control)",
            [
                make_packet(
                    source_ip="10.10.10.10",
                    protocol="TCP",
                    source_port=53000,
                    destination_port=443,
                    tcp_flags="A",
                )
            ],
            set(),
        )
    )

    # Detector uses > PORT_THRESHOLD, so 11 unique destination ports cross a threshold of 10.
    port_scan_packets = [
        make_packet(
            source_ip="10.10.10.50",
            source_port=50000 + i,
            destination_port=10000 + i,
            tcp_flags="S",
        )
        for i in range(11)
    ]
    cases.append(("Brute Force indicator", brute_force_packets, {"Brute Force"}))

    # The SYN-Flood scenario also meets the brute-force-indicator rule at 15 attempts.
    # At 30 SYN packets, the SYN Flood rule is checked first and also triggers.
    syn_flood_packets = [
        make_packet(
            source_ip="10.10.10.70",
            source_port=52000 + i,
            destination_port=80,
            tcp_flags="S",
        )
        for i in range(30)
    ]
    cases.append(
        (
            "SYN Flood (also matches Brute Force indicator)",
            syn_flood_packets,
            {"Brute Force", "SYN Flood"},
        )
    )

    icmp_packets = [
        make_packet(
            source_ip="10.10.10.80",
            protocol="ICMP",
            source_port=None,
            destination_port=None,
            tcp_flags=None,
        )
        for _ in range(50)
    ]
    cases.append(("ICMP Flood", icmp_packets, {"ICMP Flood"}))

    # These are service-port indicators, not proof that a connection is malicious.
    service_cases = [
        ("FTP service-port indicator", "10.10.10.91", 21, "Suspicious FTP Activity"),
        ("Telnet service-port indicator", "10.10.10.92", 23, "Suspicious Telnet Activity"),
        ("SMB service-port indicator", "10.10.10.93", 445, "Suspicious SMB Activity"),
        ("RDP service-port indicator", "10.10.10.94", 3389, "Suspicious RDP Activity"),
    ]
    for name, source_ip, port, expected_type in service_cases:
        packets = [
            make_packet(
                source_ip=source_ip,
                source_port=54000,
                destination_port=port,
                tcp_flags="A",
            )
        ]
        cases.append((name, packets, {expected_type}))

    return cases


def save_test_alerts(events):
    """Optionally persist returned synthetic alerts with explicit test labels."""
    from database import SessionLocal
    import crud
    import schemas

    db = SessionLocal()
    saved_count = 0
    try:
        for event in events:
            packet_info = event["packet"]
            alert = event["alert"]
            alert_data = schemas.AlertCreate(
                source_ip=packet_info["source_ip"],
                attack_type=alert["attack_type"],
                severity=alert["severity"],
                risk_score=alert["risk_score"],
                reason="[SIMULATED TEST] " + alert["reason"],
                recommendation=alert["recommendation"],
            )
            created = crud.create_alert(db=db, alert=alert_data)
            saved_count += 1
            print(
                f"Saved simulated alert: ID={getattr(created, 'id', 'unknown')} "
                f"type={alert['attack_type']}"
            )
    except Exception:
        db.rollback()
        raise
    finally:
        db.close()
    return saved_count


def main():
    parser = argparse.ArgumentParser(description="CyberShield IDS detector test harness")
    parser.add_argument(
        "--save-to-db",
        action="store_true",
        help="save detected synthetic alerts to the database, labelled [SIMULATED TEST]",
    )
    args = parser.parse_args()

    print("=" * 68)
    print("CYBERSHIELD IDS - CONTROLLED DETECTOR TESTS")
    print("Synthetic packet dictionaries are passed directly to detector.py.")
    print("No network packets are sent by this test harness.")
    print("=" * 68)

    results = []
    all_events = []
    for name, packets, expected in build_test_cases():
        result = run_case(name, packets, expected)
        results.append(result)
        all_events.extend(result["events"])

    passed_count = sum(1 for result in results if result["passed"])
    print("\n" + "=" * 68)
    print(f"SUMMARY: {passed_count}/{len(results)} tests passed")
    print(f"Alert events returned by detector: {len(all_events)}")

    if args.save_to_db:
        try:
            saved = save_test_alerts(all_events)
            print(f"Synthetic test alerts saved to database: {saved}")
            print("They are labelled [SIMULATED TEST] in the alert reason.")
        except Exception as exc:
            print("DATABASE SAVE FAILED:", exc)
            raise SystemExit(2)
    else:
        print("Database unchanged. Use --save-to-db only when you want labelled test alerts on the dashboard.")

    print("=" * 68)
    if passed_count != len(results):