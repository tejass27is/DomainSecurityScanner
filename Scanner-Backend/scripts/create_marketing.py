import os
import sys
import uuid
from dotenv import load_dotenv

sys.path.insert(0, os.path.abspath(os.path.join(os.path.dirname(__file__), "..")))
load_dotenv()

from app.api.auth.service import hashPassword
from app.db.base import SessionLocal
from app.db.models import User


def create_marketing_user():
    email = os.getenv("MARKETING_EMAIL")
    password = os.getenv("MARKETING_PASSWORD")

    if not email or not password:
        print("Skipping marketing user creation: MARKETING_EMAIL/MARKETING_PASSWORD not set in .env")
        return

    email = email.lower().strip()

    db = SessionLocal()
    try:
        existing_user = db.query(User).filter(User.email == email).first()
        if existing_user:
            return

        new_marketing = User(
            user_id=str(uuid.uuid4()),
            email=email,
            password=hashPassword(password),
            role="marketing",
            org_id=None,
            email_verified=True,
        )

        db.add(new_marketing)
        db.commit()
        print(f"Marketing user '{email}' auto-created successfully.")
    except Exception as e:
        db.rollback()
        raise RuntimeError(f"An error occurred while creating marketing user: {e}") from e
    finally:
        db.close()


if __name__ == "__main__":
    create_marketing_user()
