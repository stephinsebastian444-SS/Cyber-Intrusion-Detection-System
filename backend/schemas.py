from pydantic import BaseModel


# ----------------------------
# User Schema
# ----------------------------
class UserCreate(BaseModel):
    username: str
    password: str


# ----------------------------
# Alert Schema
# ----------------------------
class AlertResponse(BaseModel):
    source_ip: str
    attack_type: str
    severity: str
    risk_score: int
    reason: str
    recommendation: str