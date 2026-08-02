from datetime import datetime
from pydantic import BaseModel


# ==========================================
# User Schemas
# ==========================================

class UserCreate(BaseModel):
    username: str
    password: str


class UserLogin(BaseModel):
    username: str
    password: str


class UserResponse(BaseModel):
    id: int
    username: str

    class Config:
        from_attributes = True


class LoginResponse(BaseModel):
    message: str
    username: str


# ==========================================
# Alert Schemas
# ==========================================

class AlertCreate(BaseModel):
    source_ip: str
    attack_type: str
    severity: str
    risk_score: int
    reason: str
    recommendation: str


class AlertUpdate(BaseModel):
    attack_type: str | None = None
    severity: str | None = None
    risk_score: int | None = None
    reason: str | None = None
    recommendation: str | None = None

class AlertResponse(BaseModel):
    id: int
    timestamp: datetime

    source_ip: str
    attack_type: str
    severity: str
    risk_score: int
    reason: str
    recommendation: str

    class Config:
        from_attributes = True


# ==========================================
# Packet Schemas
# ==========================================

class PacketResponse(BaseModel):
    id: int
    timestamp: datetime

    source_ip: str
    destination_ip: str

    protocol: str

    source_port: int | None = None
    destination_port: int | None = None

    packet_size: int

    class Config:
        from_attributes = True


# ==========================================
# Dashboard Schema
# ==========================================

class DashboardStats(BaseModel):
    total_packets: int
    total_alerts: int
    critical_alerts: int
    high_alerts: int