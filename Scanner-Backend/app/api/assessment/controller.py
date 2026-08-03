from sqlalchemy.orm import Session
from app.db.models import UserAssessment
from app.api.assessment.schemas import UserAssessmentData

SECTION_FIELDS = (
    "authentication",
    "web_browsing",
    "emails",
    "messaging",
    "social_media",
    "networks",
    "mobile_devices",
    "personal_computers",
    "smart_home",
    "personal_finance",
    "human_aspect",
    "physical_security",
)


def _normalize_section(section: dict | None) -> dict:
    if not isinstance(section, dict):
        return {}

    normalized = {}
    ignored_values = {}

    for key, value in section.items():
        if not isinstance(value, bool):
            continue

        if key.startswith("ignored_"):
            ignored_values[key.removeprefix("ignored_")] = value
            continue

        normalized[key] = value

    for item_id, is_ignored in ignored_values.items():
        if item_id not in normalized and is_ignored:
            normalized[item_id] = False

    return normalized


def save_assessment_data(body: UserAssessmentData, user_id: str, db: Session) -> UserAssessment:
    row = db.query(UserAssessment).filter(UserAssessment.user_id == user_id).first()
    
    data_dict = body.dict(exclude_unset=True)
    
    if not row:
        row = UserAssessment(user_id=user_id)
        db.add(row)
        
    for key, val in data_dict.items():
        if hasattr(row, key) and val is not None:
            setattr(row, key, _normalize_section(val))
            
    db.commit()
    db.refresh(row)
    return row

def get_assessment_data(user_id: str, db: Session) -> dict:
    row = db.query(UserAssessment).filter(UserAssessment.user_id == user_id).first()
    if not row:
        return {}

    normalized_sections = {}
    has_changes = False

    for field in SECTION_FIELDS:
        current_value = getattr(row, field)
        normalized_value = _normalize_section(current_value)
        normalized_sections[field] = normalized_value

        if current_value != normalized_value:
            setattr(row, field, normalized_value)
            has_changes = True

    if has_changes:
        db.commit()
        db.refresh(row)

    return normalized_sections
