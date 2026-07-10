from sqlalchemy.orm import Session
from passlib.context import CryptContext

import models
import schemas

pwd_context = CryptContext(schemes=["bcrypt"], deprecated="auto")


def get_password_hash(password: str):
    return pwd_context.hash(password)


def create_user(db: Session, user: schemas.UserCreate):
    hashed_password = get_password_hash(user.password)

    db_user = models.User(
        username=user.username,
        password=hashed_password
    )

    db.add(db_user)
    db.commit()
    db.refresh(db_user)

    return db_user

def get_users(db):
    return db.query(models.User).all()

def get_user_by_username(db, username):
    return db.query(models.User).filter(models.User.username == username).first()

from passlib.context import CryptContext

pwd_context = CryptContext(schemes=["bcrypt"], deprecated="auto")

def verify_password(plain_password, hashed_password):
    return pwd_context.verify(plain_password, hashed_password)


def authenticate_user(db, username, password):
    user = get_user_by_username(db, username)

    if not user:
        return None

    if not verify_password(password, user.password):
        return None

    return user