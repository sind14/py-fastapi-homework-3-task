from pydantic import BaseModel, EmailStr, field_validator

from database import accounts_validators


class UserRegRequestSchema(BaseModel):
    email: EmailStr
    password: str

    @field_validator("password")
    @classmethod
    def validate_password(cls, value: str):
        return accounts_validators.validate_password_strength(value)


class UserRegResponseSchema(BaseModel):
    id: int
    email: EmailStr


    class Config:
        from_attributes = True


class UserActRequestSchema(BaseModel):
    email: EmailStr
    token: str


class UserActResponseSchema(BaseModel):
    message: str


class PasswordResetRequestSchema(BaseModel):
    email: EmailStr


class PasswordResetResponseSchema(BaseModel):
    message: str


class PasswordResetCompleteRequestSchema(BaseModel):
    email: EmailStr
    token: str
    password: str

    @field_validator("password")
    @classmethod
    def validate_password(cls, value: str) -> str:
        return accounts_validators.validate_password_strength(value)


class PasswordResetCompleteResponseSchema(BaseModel):
    message: str


class UserLoginResponseSchema(BaseModel):
    access_token: str
    refresh_token: str
    token_type: str = "bearer"


class UserLoginRequestSchema(BaseModel):
    email: EmailStr
    password: str


class RefreshTokenRequestSchema(BaseModel):
    refresh_token: str


class RefreshTokenResponseSchema(BaseModel):
    access_token: str
