import time

from database import SessionLocal
import models


# ============================================================
# CONFIGURATION
# ============================================================

CLEANUP_INTERVAL_SECONDS = 3600


# ============================================================
# DELETE ALL PACKETS
# ============================================================

def delete_packets():

    db = SessionLocal()

    try:

        deleted_count = (
            db.query(models.Packet)
            .delete(
                synchronize_session=False
            )
        )

        db.commit()

        print(
            f"[CLEANUP] Deleted {deleted_count} packet(s). "
            "Alerts were preserved."
        )

    except Exception as e:

        db.rollback()

        print(
            "[CLEANUP] Database Error:",
            e
        )

    finally:

        db.close()


# ============================================================
# START CLEANUP SERVICE
# ============================================================

print("===================================")
print("Cyber IDS Packet Cleanup Started")
print("Packets will be cleared every hour.")
print("Alerts will be preserved.")
print("===================================")


while True:

    delete_packets()

    time.sleep(
        CLEANUP_INTERVAL_SECONDS
    )