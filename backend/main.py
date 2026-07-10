from fastapi import FastAPI

from database import engine
import models

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