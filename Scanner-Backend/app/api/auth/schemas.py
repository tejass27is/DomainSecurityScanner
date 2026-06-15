from pydantic import BaseModel, EmailStr

class RegisterRequest(BaseModel):
    email: EmailStr
    password: str
    domain: str
    name: str | None = None
    invite_token: str | None = None
    captcha_token: str | None = None

class LoginRequest(BaseModel):
    email: EmailStr
    password: str
    captcha_token: str | None = None


class LoginOtpVerifyRequest(BaseModel):
    email: EmailStr
    password: str
    otp: str
    captcha_token: str | None = None

class InviteRequest(BaseModel):
    email: EmailStr

class RedeemPromoRequest(BaseModel):
    code: str

class ForgotPasswordOtpRequest(BaseModel):
    email: EmailStr

class ForgotPasswordResetRequest(BaseModel):
    email: EmailStr
    otp: str
    new_password: str

class ResetPasswordRequest(BaseModel):
    old_password: str
    new_password: str

class AcceptInviteRequest(BaseModel):
    email: EmailStr
    password: str
    token: str

class OrgMembersRequest(BaseModel):
    org_id: str

class AddDomainRequest(BaseModel):
    domain: str


class VerifyEmailRequest(BaseModel):
    token: str
