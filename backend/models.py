from sqlalchemy import Column, Integer, String, DateTime
from datetime import datetime

from database import Base


# ----------------------------
# Users Table
# ----------------------------
class User(Base):
    __tablename__ = "users"

    id = Column(Integer, primary_key=True, index=True)
    username = Column(String, unique=True, nullable=False)
    password = Column(String, nullable=False)


# ----------------------------
# Packets Table
# ----------------------------
class Packet(Base):
    __tablename__ = "packets"

    id = Column(Integer, primary_key=True, index=True)
    timestamp = Column(DateTime, default=datetime.utcnow)

    source_ip = Column(String, nullable=False)
    destination_ip = Column(String, nullable=False)

    protocol = Column(String, nullable=False)

    source_port = Column(Integer)
    destination_port = Column(Integer)

    packet_size = Column(Integer)


# ----------------------------
# Alerts Table
# ----------------------------
class Alert(Base):
    __tablename__ = "alerts"

    id = Column(Integer, primary_key=True, index=True)
    timestamp = Column(DateTime, default=datetime.utcnow)

    source_ip = Column(String, nullable=False)

    attack_type = Column(String, nullable=False)

    severity = Column(String, nullable=False)

    risk_score = Column(Integer)

    reason = Column(String)

    recommendation = Column(String)