from datetime import datetime
from pydantic import BaseModel, EmailStr


class BlacklistEmailRequest(BaseModel):
    email: EmailStr


class VaptBlockRequest(BaseModel):
    """Block/unblock an individual user's VAPT access — by user_id or email."""
    user_id: str | None = None
    email: str | None = None


class CreateAdminRequest(BaseModel):
    email: EmailStr


class CreateSocAnalystRequest(BaseModel):
    email: EmailStr


class PersonalEmailApprovalRequest(BaseModel):
    email: EmailStr
    notes: str | None = None


class DeleteUserRequest(BaseModel):
    user_id: str
    admin_password: str


class GeneratePromoCodeRequest(BaseModel):
    expires_at: datetime


class AssignPromoCodeRequest(BaseModel):
    promo_code: str
    email: EmailStr


class SubscriptionPlanCreate(BaseModel):
    plan_id: str | None = None
    name: str
    price: int
    icon: str | None = None
    color: str | None = None
    container_color: str | None = None
    popular: bool = False
    features: list[str] = []


class SubscriptionPlanUpdate(BaseModel):
    name: str | None = None
    price: int | None = None
    icon: str | None = None
    color: str | None = None
    container_color: str | None = None
    popular: bool | None = None
    features: list[str] | None = None


class SubscriptionPlanOut(BaseModel):
    plan_id: str
    name: str
    price: int
    icon: str | None = None
    color: str | None = None
    container_color: str | None = None
    popular: bool = False
    features: list[str] = []

    class Config:
        orm_mode = True
