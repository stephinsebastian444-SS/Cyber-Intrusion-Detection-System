from fastapi import FastAPI, Depends, HTTPException
from sqlalchemy.orm import Session
from fastapi.middleware.cors import CORSMiddleware

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
