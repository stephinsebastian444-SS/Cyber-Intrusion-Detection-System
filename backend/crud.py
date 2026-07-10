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