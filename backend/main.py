from fastapi import FastAPI, Depends, HTTPException
from sqlalchemy.orm import Session
from fastapi.middleware.cors import CORSMiddleware
from sqlalchemy import text

import models
import schemas
import crud

from database import engine, get_db
# Create FastAPI application
app = FastAPI(
    title="Cyber Intrusion Detection System",
    description="Backend API for monitoring network traffic and detecting suspicious activities.",
    version="1.0"
)
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

models.Base.metadata.create_all(bind=engine)

# Home Route
@app.get("/")
def home():
    return {
        "message": "Welcome to Cyber IDS",
        "status": "Running"
    }

# About Route
@app.get("/about")
def about():
    return {
        "project": "Cyber Intrusion Detection System",
        "developer": "Your Team",
        "version": "1.0"
    }

# Health Check Route
@app.get("/health")
def health():
    return {
        "server": "Healthy"
    }

# User Creation Route
@app.post("/users")
def create_user(user: schemas.UserCreate, db: Session = Depends(get_db)):

    existing_user = crud.get_user_by_username(db, user.username)

    if existing_user:
        raise HTTPException(
            status_code=400,
            detail="Username already exists."
        )

    created_user = crud.create_user(db=db, user=user)

    return {
        "message": "User created successfully",
        "username": created_user.username
    }

@app.post("/login", response_model=schemas.LoginResponse)
def login(user: schemas.UserLogin, db: Session = Depends(get_db)):

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

@app.get("/users", response_model=list[schemas.UserResponse])
def get_users(db: Session = Depends(get_db)):
    return crud.get_users(db)

@app.post("/alerts", response_model=schemas.AlertResponse)
def create_alert(alert: schemas.AlertCreate, db: Session = Depends(get_db)):
    return crud.create_alert(db=db, alert=alert)

@app.get("/alerts", response_model=list[schemas.AlertResponse])
def get_alerts(db: Session = Depends(get_db)):
    return crud.get_alerts(db)

@app.get("/alerts/{alert_id}", response_model=schemas.AlertResponse)
def get_alert(alert_id: int, db: Session = Depends(get_db)):

    alert = crud.get_alert(db, alert_id)

    if alert is None:
        raise HTTPException(
            status_code=404,
            detail="Alert not found."
        )

    return alert

@app.delete("/alerts/{alert_id}")
def delete_alert(alert_id: int, db: Session = Depends(get_db)):

    deleted = crud.delete_alert(db, alert_id)

    if deleted is None:
        raise HTTPException(
            status_code=404,
            detail="Alert not found."
        )

    return {
        "message": "Alert deleted successfully."
    }

@app.put("/alerts/{alert_id}", response_model=schemas.AlertResponse)
def update_alert(
    alert_id: int,
    alert: schemas.AlertUpdate,
    db: Session = Depends(get_db)
):

    updated = crud.update_alert(
        db,
        alert_id,
        alert.model_dump(exclude_unset=True)
    )

    if updated is None:
        raise HTTPException(
            status_code=404,
            detail="Alert not found."
        )

    return updated

@app.get("/packets", response_model=list[schemas.PacketResponse])
def get_packets(db: Session = Depends(get_db)):
    return crud.get_packets(db)

@app.get("/packets/{packet_id}", response_model=schemas.PacketResponse)
def get_packet(packet_id: int, db: Session = Depends(get_db)):

    packet = crud.get_packet(db, packet_id)

    if packet is None:
        raise HTTPException(
            status_code=404,
            detail="Packet not found."
        )

    return packet

@app.get("/live")
def live_packets(db: Session = Depends(get_db)):

    packets = (
        db.query(models.Packet)
        .order_by(models.Packet.timestamp.desc())
        .limit(30)
        .all()
    )

    return packets

@app.get("/dashboard")
def dashboard(db: Session = Depends(get_db)):

    alerts = crud.get_alerts(db)
    packets = crud.get_packets(db)

    critical = len([a for a in alerts if a.severity == "Critical"])
    high = len([a for a in alerts if a.severity == "High"])
    medium = len([a for a in alerts if a.severity == "Medium"])
    low = len([a for a in alerts if a.severity == "Low"])

    return {
        "total_packets": len(packets),
        "total_alerts": len(alerts),
        "critical_alerts": critical,
        "high_alerts": high,
        "medium_alerts": medium,
        "low_alerts": low
    }

@app.get("/status")
def status(db: Session = Depends(get_db)):

    try:
        db.execute(text("SELECT 1"))
        database_status = "Connected"
    except:
        database_status = "Disconnected"

    return {
        "system": "Cyber IDS",
        "backend": "Online",
        "database": database_status,
        "sniffer": "Running"
    }

