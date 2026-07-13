from pydantic import BaseModel
from datetime import datetime

# ----------------------------
# User Schema
# ----------------------------
class UserCreate(BaseModel):
    username: str
    password: str

class UserResponse(BaseModel):
    id: int
    username: str

    class Config:
        from_attributes = True    

# ----------------------------
# Alert Schema
# ----------------------------
class AlertCreate(BaseModel):
    source_ip: str
    attack_type: str
    severity: str
    risk_score: int
    reason: str
    recommendation: str

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

class UserLogin(BaseModel):
    username: str
    password: str


class LoginResponse(BaseModel):
    message: str
    username: str    