import os

os.environ.setdefault("DATABASE_URL", "sqlite:///:memory:")

from sqlalchemy.orm import Session

from app.db.base import Base, engine
from app.api.admin.service import create_public_report_request


def test_create_public_report_request_persists_summary():
    Base.metadata.drop_all(bind=engine, checkfirst=True)
    Base.metadata.create_all(bind=engine)

    db = Session(bind=engine)
    try:
        record = create_public_report_request(
            db,
            email="user@example.com",
            domain="example.com",
            report_payload={
                "score": 88,
                "grade_label": "Good",
                "categories": [{"name": "Application Security", "finding_count": 1}],
            },
        )

        assert record.email == "user@example.com"
        assert record.domain == "example.com"
        assert record.report_payload["score"] == 88
        assert record.report_payload["grade_label"] == "Good"
    finally:
        db.close()
