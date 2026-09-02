from fastapi import FastAPI, Depends, HTTPException
from sqlalchemy.orm import Session
from fastapi.middleware.cors import CORSMiddleware
from sqlalchemy import text

import models
import schemas
import crud

from database import engine, get_db

import subprocess
import sys
from pathlib import Path


# ============================================================
# BACKGROUND PROCESSES
# ============================================================

sniffer_process = None
cleanup_process = None


# ============================================================
# FASTAPI APPLICATION
# ============================================================

app = FastAPI(
    title="Cyber Intrusion Detection System",
    description="Backend API for monitoring network traffic and detecting suspicious activities.",
    version="1.0"
)


# ============================================================
# CORS
# ============================================================

app.add_middleware(
    CORSMiddleware,
    allow_origins=[
        "http://127.0.0.1:5500",
        "http://localhost:5500"
    ],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)


# ============================================================
# DATABASE TABLE CREATION
# ============================================================

models.Base.metadata.create_all(bind=engine)


# ============================================================
# START SNIFFER
# ============================================================

@app.on_event("startup")
def start_sniffer():

    global sniffer_process

    try:

        sniffer_path = Path(__file__).with_name("sniffer.py")

        print()
        print("===================================")
        print("Starting Cyber IDS Sniffer...")
        print("===================================")

        sniffer_process = subprocess.Popen(
            [
                sys.executable,
                str(sniffer_path)
            ]
        )

        print(
            f"Sniffer started with PID: "
            f"{sniffer_process.pid}"
        )

        print("===================================")
        print()

    except Exception as e:

        print()
        print("===================================")
        print("ERROR STARTING SNIFFER")
        print("===================================")
        print(e)
        print("===================================")
        print()


# ============================================================
# START CLEANUP SERVICE
# ============================================================

@app.on_event("startup")
def start_cleanup():

    global cleanup_process

    try:

        cleanup_path = Path(__file__).with_name("cleanup.py")

        print()
        print("===================================")
        print("Starting Packet Cleanup Service...")
        print("===================================")

        cleanup_process = subprocess.Popen(
            [
                sys.executable,
                str(cleanup_path)
            ]
        )

        print(
            f"Cleanup service started with PID: "
            f"{cleanup_process.pid}"
        )

        print("===================================")
        print()

    except Exception as e:

        print()
        print("===================================")
        print("ERROR STARTING CLEANUP SERVICE")
        print("===================================")
        print(e)
        print("===================================")
        print()


# ============================================================
# STOP SNIFFER
# ============================================================

@app.on_event("shutdown")
def stop_sniffer():

    global sniffer_process

    if sniffer_process is not None:

        try:

            if sniffer_process.poll() is None:

                print()
                print("Stopping Cyber IDS Sniffer...")

                sniffer_process.terminate()

                sniffer_process.wait(
                    timeout=5
                )

                print("Sniffer stopped.")

        except Exception as e:

            print(
                "Error stopping sniffer:",
                e
            )

        finally:

            sniffer_process = None


# ============================================================
# STOP CLEANUP SERVICE
# ============================================================

@app.on_event("shutdown")
def stop_cleanup():

    global cleanup_process

    if cleanup_process is not None:

        try:

            if cleanup_process.poll() is None:

                print(
                    "Stopping Packet Cleanup Service..."
                )

                cleanup_process.terminate()

                cleanup_process.wait(
                    timeout=5
                )

                print(
                    "Cleanup service stopped."
                )

        except Exception as e:

            print(
                "Error stopping cleanup service:",
                e
            )

        finally:

            cleanup_process = None


# ============================================================
# HOME ROUTE
# ============================================================

@app.get("/")
def home():

    return {
        "message": "Welcome to Cyber IDS",
        "status": "Running"
    }


# ============================================================
# ABOUT ROUTE
# ============================================================

@app.get("/about")
def about():

    return {
        "project": "Cyber Intrusion Detection System",
        "developer": "Your Team",
        "version": "1.0"
    }


# ============================================================
# HEALTH CHECK
# ============================================================

@app.get("/health")
def health():

    return {
        "server": "Healthy"
    }


# ============================================================
# USER CREATION
# ============================================================

@app.post("/users")
def create_user(
    user: schemas.UserCreate,
    db: Session = Depends(get_db)
):

    existing_user = crud.get_user_by_username(
        db,
        user.username
    )

    if existing_user:

        raise HTTPException(
            status_code=400,
            detail="Username already exists."
        )

    created_user = crud.create_user(
        db=db,
        user=user
    )

    return {
        "message": "User created successfully",
        "username": created_user.username
    }


# ============================================================
# LOGIN
# ============================================================

@app.post(
    "/login",
    response_model=schemas.LoginResponse
)
def login(
    user: schemas.UserLogin,
    db: Session = Depends(get_db)
):

    authenticated_user = crud.authenticate_user(
        db=db,
        username=user.username,
        password=user.password
    )

    if authenticated_user is None:

        raise HTTPException(
            status_code=401,
            detail="Invalid username or password."
        )

    return {
        "message": "Login successful",
        "username": authenticated_user.username
    }


# ============================================================
# GET USERS
# ============================================================

@app.get(
    "/users",
    response_model=list[schemas.UserResponse]
)
def get_users(
    db: Session = Depends(get_db)
):

    return crud.get_users(db)


# ============================================================
# CREATE ALERT
# ============================================================

@app.post(
    "/alerts",
    response_model=schemas.AlertResponse
)
def create_alert(
    alert: schemas.AlertCreate,
    db: Session = Depends(get_db)
):

    return crud.create_alert(
        db=db,
        alert=alert
    )


# ============================================================
# GET ALERTS
# ============================================================

@app.get(
    "/alerts",
    response_model=list[schemas.AlertResponse]
)
def get_alerts(
    db: Session = Depends(get_db)
):

    return crud.get_alerts(db)


# ============================================================
# GET SINGLE ALERT
# ============================================================

@app.get(
    "/alerts/{alert_id}",
    response_model=schemas.AlertResponse
)
def get_alert(
    alert_id: int,
    db: Session = Depends(get_db)
):

    alert = crud.get_alert(
        db,
        alert_id
    )

    if alert is None:

        raise HTTPException(
            status_code=404,
            detail="Alert not found."
        )

    return alert


# ============================================================
# DELETE ALERT
# ============================================================

@app.delete("/alerts/{alert_id}")
def delete_alert(
    alert_id: int,
    db: Session = Depends(get_db)
):

    deleted = crud.delete_alert(
        db,
        alert_id
    )

    if deleted is None:

        raise HTTPException(
            status_code=404,
            detail="Alert not found."
        )

    return {
        "message": "Alert deleted successfully."
    }


# ============================================================
# UPDATE ALERT
# ============================================================

@app.put(
    "/alerts/{alert_id}",
    response_model=schemas.AlertResponse
)
def update_alert(
    alert_id: int,
    alert: schemas.AlertUpdate,
    db: Session = Depends(get_db)
):

    updated = crud.update_alert(
        db,
        alert_id,
        alert.model_dump(
            exclude_unset=True
        )
    )

    if updated is None:

        raise HTTPException(
            status_code=404,
            detail="Alert not found."
        )

    return updated


# ============================================================
# GET PACKETS
# ============================================================

@app.get(
    "/packets",
    response_model=list[schemas.PacketResponse]
)
def get_packets(
    db: Session = Depends(get_db)
):

    return crud.get_packets(db)


# ============================================================
# GET SINGLE PACKET
# ============================================================

@app.get(
    "/packets/{packet_id}",
    response_model=schemas.PacketResponse
)
def get_packet(
    packet_id: int,
    db: Session = Depends(get_db)
):

    packet = crud.get_packet(
        db,
        packet_id
    )

    if packet is None:

        raise HTTPException(
            status_code=404,
            detail="Packet not found."
        )

    return packet


# ============================================================
# LIVE PACKETS
# ============================================================

@app.get("/live")
def live_packets(
    db: Session = Depends(get_db)
):

    packets = (
        db.query(models.Packet)
        .order_by(
            models.Packet.timestamp.desc()
        )
        .limit(30)
        .all()
    )

    return packets


# ============================================================
# DASHBOARD
# ============================================================

@app.get("/dashboard")
def dashboard(
    db: Session = Depends(get_db)
):

    alerts = crud.get_alerts(db)
    packets = crud.get_packets(db)

    # --------------------------------------------------------
    # Alert counts
    # --------------------------------------------------------

    critical = len([
        a for a in alerts
        if a.severity == "Critical"
    ])

    high = len([
        a for a in alerts
        if a.severity == "High"
    ])

    medium = len([
        a for a in alerts
        if a.severity == "Medium"
    ])

    low = len([
        a for a in alerts
        if a.severity == "Low"
    ])

    # --------------------------------------------------------
    # Protocol counts
    # --------------------------------------------------------

    tcp = len([
        p for p in packets
        if p.protocol == "TCP"
    ])

    udp = len([
        p for p in packets
        if p.protocol == "UDP"
    ])

    icmp = len([
        p for p in packets
        if p.protocol == "ICMP"
    ])

    other = len([
        p for p in packets
        if p.protocol not in [
            "TCP",
            "UDP",
            "ICMP"
        ]
    ])

    return {
        "total_packets": len(packets),
        "total_alerts": len(alerts),

        "critical_alerts": critical,
        "high_alerts": high,
        "medium_alerts": medium,
        "low_alerts": low,

        "tcp_packets": tcp,
        "udp_packets": udp,
        "icmp_packets": icmp,
        "other_packets": other
    }


# ============================================================
# STATUS
# ============================================================

@app.get("/status")
def status(
    db: Session = Depends(get_db)
):

    # --------------------------------------------------------
    # Database status
    # --------------------------------------------------------

    try:

        db.execute(
            text("SELECT 1")
        )

        database_status = "Connected"

    except Exception:

        database_status = "Disconnected"


    # --------------------------------------------------------
    # Sniffer status
    # --------------------------------------------------------

    if (
        sniffer_process is not None
        and
        sniffer_process.poll() is None
    ):

        sniffer_status = "Running"

    else:

        sniffer_status = "Stopped"


    # --------------------------------------------------------
    # Cleanup status
    # --------------------------------------------------------

    if (
        cleanup_process is not None
        and
        cleanup_process.poll() is None
    ):

        cleanup_status = "Running"

    else:

        cleanup_status = "Stopped"


    return {
        "system": "Cyber IDS",
        "backend": "Online",
        "database": database_status,
        "sniffer": sniffer_status,
        "cleanup": cleanup_status
    }