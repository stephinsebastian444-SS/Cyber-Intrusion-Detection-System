from pydantic import BaseModel


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
class AlertResponse(BaseModel):
    source_ip: str
    attack_type: str
    severity: str
    risk_score: int
    reason: str
    recommendation: str

class UserLogin(BaseModel):
    username: str
    password: str


class LoginResponse(BaseModel):
    message: str
    username: str    