from fastapi import APIRouter, Depends
from sqlalchemy.orm import Session
from app.core.middleware import protect
from app.db.base import get_db
from app.api.assessment.schemas import UserAssessmentData
from app.api.assessment.controller import save_assessment_data, get_assessment_data

router = APIRouter(prefix="/assessment", tags=["assessment"])

@router.get("/")
async def get_assessment(
    db: Session = Depends(get_db),
    current_user=Depends(protect),
):
    data = get_assessment_data(current_user.user_id, db)
    return {"success": True, "data": data}

@router.post("/submit")
async def save_assessment(
    body: UserAssessmentData,
    db: Session = Depends(get_db),
    current_user=Depends(protect),
):
    row = save_assessment_data(body, current_user.user_id, db)
    return {"success": True, "message": "Assessment saved successfully"}
