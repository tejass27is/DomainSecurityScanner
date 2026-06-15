from pydantic import BaseModel, EmailStr
from datetime import datetime
from datetime import datetime


class BlacklistEmailRequest(BaseModel):
    email: EmailStr


class CreateAdminRequest(BaseModel):
    email: EmailStr
