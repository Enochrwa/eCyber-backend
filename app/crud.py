from sqlalchemy.orm import Session
from models import user as models
from schemas import user as schemas
from .auth import get_password_hash, verify_password

# User


def get_user_by_email(db: Session, email: str):
    return db.query(models.User).filter(models.User.email == email).first()


def create_user(db: Session, user: schemas.UserCreate):
    hashed_pw = get_password_hash(user.password)
    db_user = models.User(
        email=user.email, name=user.name, hashed_password=hashed_pw  # 👈 include name
    )
    db.add(db_user)
    db.commit()
    db.refresh(db_user)
    return db_user


def authenticate_user(db: Session, email: str, password: str):
    user = get_user_by_email(db, email)
    if user and verify_password(password, user.hashed_password):
        return user
    return None


# Notes


def create_note(db: Session, note: schemas.NoteCreate, user_id: int):
    db_note = models.Note(**note.dict(), owner_id=user_id)
    db.add(db_note)
    db.commit()
    db.refresh(db_note)
    return db_note


def get_notes(db: Session, user_id: int):
    return db.query(models.Note).filter(models.Note.owner_id == user_id).all()


def get_note(db: Session, note_id: int):
    return db.query(models.Note).filter(models.Note.id == note_id).first()


def delete_note(db: Session, note_id: int):
    note = get_note(db, note_id)
    db.delete(note)
    db.commit()


def update_note(db: Session, note_id: int, content: str):
    note = get_note(db, note_id)
    note.content = content
    db.commit()
    db.refresh(note)
    return note
