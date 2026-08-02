from datetime import datetime

from sqlalchemy import Column, Integer, String, DateTime

from database import Base


# ==========================================
# Users Table
# ==========================================

class User(Base):
    __tablename__ = "users"

    id = Column(Integer, primary_key=True, index=True)

    username = Column(
        String,
        unique=True,
        nullable=False,
        index=True
    )

    password = Column(
        String,
        nullable=False
    )


# ==========================================
# Packets Table
# ==========================================

class Packet(Base):
    __tablename__ = "packets"

    id = Column(Integer, primary_key=True, index=True)

    timestamp = Column(
        DateTime,
        default=datetime.utcnow,
        nullable=False
    )

    source_ip = Column(
        String,
        nullable=False,
        index=True
    )

    destination_ip = Column(
        String,
        nullable=False,
        index=True
    )

    protocol = Column(
        String,
        nullable=False
    )

    source_port = Column(Integer, nullable=True)

    destination_port = Column(Integer, nullable=True)

    packet_size = Column(Integer, nullable=False)


# ==========================================
# Alerts Table
# ==========================================

class Alert(Base):
    __tablename__ = "alerts"

    id = Column(Integer, primary_key=True, index=True)

    timestamp = Column(
        DateTime,
        default=datetime.utcnow,
        nullable=False
    )

    source_ip = Column(
        String,
        nullable=False,
        index=True
    )

    attack_type = Column(
        String,
        nullable=False
    )

    severity = Column(
        String,
        nullable=False,
        index=True
    )

    risk_score = Column(
        Integer,
        nullable=False
    )

    reason = Column(
        String,
        nullable=False
    )

    recommendation = Column(
        String,
        nullable=False
    )