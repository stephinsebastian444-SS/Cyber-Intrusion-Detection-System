from fastapi import FastAPI, Depends
from sqlalchemy.orm import Session

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

models.Base.metadata.create_all(bind=engine)

# Home Route
@app.get("/")
def home():
    return {
        "message": "Welcome to Cyber IDS",
        "status": "Running"
    }

# Status Route
@app.get("/status")
def status():
    return {
        "system": "Cyber IDS",
        "backend": "Online",
        "database": "Not Connected",
        "sniffer": "Not Running"
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
    created_user = crud.create_user(db=db, user=user)

    return {
        "message": "User created successfully",
        "username": created_user.username
    }