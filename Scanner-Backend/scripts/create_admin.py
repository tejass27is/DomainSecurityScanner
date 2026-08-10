import os
import sys
import uuid
from dotenv import load_dotenv

sys.path.insert(0, os.path.abspath(os.path.join(os.path.dirname(__file__), "..")))
load_dotenv()

from app.api.auth.service import hashPassword
from app.db.base import SessionLocal
from app.db.models import User


def create_admin_user():
    email = os.getenv("ADMIN_EMAIL")
    password = os.getenv("ADMIN_PASSWORD")

    missing = []
    if not email:
        missing.append("ADMIN_EMAIL")
    if not password:
        missing.append("ADMIN_PASSWORD")
    if missing:
        raise RuntimeError(f"{', '.join(missing)} missing in .env")

    email = email.lower().strip()

    db = SessionLocal()
    try:
        existing_user = db.query(User).filter(User.email == email).first()
        if existing_user:
            return

        new_admin = User(
            user_id=str(uuid.uuid4()),
            email=email,
            password=hashPassword(password),
            role="admin",
            org_id=None,
            email_verified=True,
        )

        db.add(new_admin)
        db.commit()
        print(f"Admin user '{email}' auto-created successfully.")
    except Exception as e:
        db.rollback()
        raise RuntimeError(f"An error occurred while creating admin: {e}") from e
    finally:
        db.close()


if __name__ == "__main__":
    create_admin_user()
