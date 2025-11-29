from datetime import datetime, timezone
from typing import cast
from fastapi import APIRouter, Depends, status, HTTPException
from sqlalchemy import select, delete
from sqlalchemy.exc import SQLAlchemyError
from sqlalchemy.ext.asyncio import AsyncSession
from config import get_jwt_auth_manager, get_settings, BaseAppSettings
from database import (
    get_db,
    UserModel,
    UserGroupModel,
    UserGroupEnum,
    ActivationTokenModel,
    PasswordResetTokenModel,
    RefreshTokenModel
)
from exceptions import TokenExpiredError, InvalidTokenError
from schemas import UserLoginResponseSchema
from schemas.accounts import (
    UserRegRequestSchema,
    UserRegResponseSchema,
    UserActRequestSchema,
    UserActResponseSchema,
    PasswordResetRequestSchema,
    PasswordResetResponseSchema,
    PasswordResetCompleteResponseSchema,
    PasswordResetCompleteRequestSchema,
    UserLoginRequestSchema,
    RefreshTokenResponseSchema,
    RefreshTokenRequestSchema,
)
from security.interfaces import JWTAuthManagerInterface

router = APIRouter()


@router.post("/register/", response_model=UserRegResponseSchema, status_code=status.HTTP_201_CREATED)
async def register_user(user_data: UserRegRequestSchema, db: AsyncSession = Depends(get_db)):
    stmt = select(UserModel).where(UserModel.email == user_data.email)
    result = await db.execute(stmt)
    existing_user = result.scalars().first()

    if existing_user:
        raise HTTPException(
            status_code=status.HTTP_409_CONFLICT,
            detail=f"A user with this email {user_data.email} already exists.")

    stmt_group = select(UserGroupModel).where(UserGroupModel.name == UserGroupEnum.USER)
    result_group = await db.execute(stmt_group)
    user_group = result_group.scalars().first()

    if not user_group:
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail="An error occurred during user creation."
        )

    try:

        new_user = UserModel.create(
            email=user_data.email,
            raw_password=user_data.password,
            group_id=cast(int, user_group.id),
        )
        db.add(new_user)
        await db.flush()

        activation_token = ActivationTokenModel(user_id=cast(int, new_user.id))
        db.add(activation_token)
        await db.commit()
        await db.refresh(new_user)

        return UserRegResponseSchema.model_validate(new_user)

    except SQLAlchemyError:
        await db.rollback()
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail="An error occurred during user creation."
        )


@router.post("/activate/", response_model=UserActResponseSchema, status_code=status.HTTP_200_OK)
async def activate_user(activation: UserActRequestSchema, db: AsyncSession = Depends(get_db)):
    stmt = select(UserModel).where(UserModel.email == activation.email)
    result = await db.execute(stmt)
    user = result.scalars().first()

    if not user:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="Invalid or expired activation token."
        )

    if user.is_active:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="User account is already active."
        )

    stmt_token = (
        select(ActivationTokenModel).where(
            ActivationTokenModel.user_id == user.id,
            ActivationTokenModel.token == activation.token,
        )
    )
    result_token = await db.execute(stmt_token)
    activation_token = result_token.scalars().first()

    if not activation_token:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="Invalid or expired activation token."
        )

    expires_at = cast(datetime, activation_token.expires_at).replace(tzinfo=timezone.utc)
    if expires_at <= datetime.now(timezone.utc):
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="Invalid or expired activation token."
        )

    user.is_active = True
    await db.delete(activation_token)
    await db.commit()

    return UserActResponseSchema(message="User account activated successfully.")


@router.post("/password-reset/request/", response_model=PasswordResetResponseSchema, status_code=status.HTTP_200_OK)
async def password_reset_request_user(
        reset: PasswordResetRequestSchema,
        db: AsyncSession = Depends(get_db),
):
    stmt = select(UserModel).where(UserModel.email == reset.email)
    result = await db.execute(stmt)
    user = result.scalars().first()

    if user and user.is_active:
        stmt_delete = delete(PasswordResetTokenModel).where(
            PasswordResetTokenModel.user_id == user.id
        )
        await db.execute(stmt_delete)

        reset_token = PasswordResetTokenModel(user_id=cast(int, user.id))
        db.add(reset_token)
        await db.commit()

    return PasswordResetResponseSchema(
        message="If you are registered, you will receive an email with instructions."
    )


@router.post(
    "/reset-password/complete/",
    response_model=PasswordResetCompleteResponseSchema,
    status_code=status.HTTP_200_OK,
)
async def reset_password_complete_user(
        reset: PasswordResetCompleteRequestSchema,
        db: AsyncSession = Depends(get_db),
):
    stmt = select(UserModel).where(UserModel.email == reset.email)
    result = await db.execute(stmt)
    user = result.scalars().first()

    if not user or not user.is_active:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="Invalid email or token."
        )

    stmt_token = (
        select(PasswordResetTokenModel).where(
            PasswordResetTokenModel.user_id == user.id,
            PasswordResetTokenModel.token == reset.token,
        )
    )
    result_token = await db.execute(stmt_token)
    reset_token = result_token.scalars().first()

    if not reset_token:
        stmt_existing_token = select(PasswordResetTokenModel).where(
            PasswordResetTokenModel.user_id == user.id,
        )
        result_existing = await db.execute(stmt_existing_token)
        existing_token = result_existing.scalars().first()
        if existing_token:
            await db.delete(existing_token)
            await db.commit()
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="Invalid email or token."
        )

    expires_at = cast(datetime, reset_token.expires_at).replace(tzinfo=timezone.utc)
    if expires_at <= datetime.now(timezone.utc):
        await db.delete(reset_token)
        await db.commit()
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="Invalid email or token."
        )

    try:
        user.password = reset.password

        await db.delete(reset_token)
        await db.commit()

        return PasswordResetCompleteResponseSchema(message="Password reset successfully.")

    except SQLAlchemyError:
        await db.rollback()
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail="An error occurred while resetting the password."
        )


@router.post("/login/", response_model=UserLoginResponseSchema, status_code=status.HTTP_201_CREATED)
async def login_user(
        login: UserLoginRequestSchema,
        db: AsyncSession = Depends(get_db),
        jwt_manager: JWTAuthManagerInterface = Depends(get_jwt_auth_manager),
        settings: BaseAppSettings = Depends(get_settings),
):
    stmt = select(UserModel).where(UserModel.email == login.email)
    result = await db.execute(stmt)
    user = result.scalars().first()

    if not user or not user.verify_password(login.password):
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Invalid email or password."
        )

    if not user.is_active:
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN,
            detail="User account is not activated."
        )

    try:
        access_token = jwt_manager.create_access_token({"user_id": user.id})
        refresh_token = jwt_manager.create_refresh_token({"user_id": user.id})

        refresh_token_record = RefreshTokenModel.create(
            user_id=cast(int, user.id),
            days_valid=settings.LOGIN_TIME_DAYS,
            token=refresh_token,
        )
        db.add(refresh_token_record)
        await db.commit()

        return UserLoginResponseSchema(
            access_token=access_token,
            refresh_token=refresh_token,
            token_type="bearer",
        )

    except SQLAlchemyError:
        await db.rollback()
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail="An error occurred while processing the request."
        )


@router.post("/refresh/", response_model=RefreshTokenResponseSchema, status_code=status.HTTP_200_OK)
async def refresh_access_token(
        refresh: RefreshTokenRequestSchema,
        db: AsyncSession = Depends(get_db),
        jwt_manager: JWTAuthManagerInterface = Depends(get_jwt_auth_manager),

):
    try:
        token = jwt_manager.decode_refresh_token(refresh.refresh_token)
        user_id = token.get("user_id")

        if not user_id:
            raise HTTPException(
                status_code=status.HTTP_400_BAD_REQUEST,
                detail="Token has expired."
            )

    except (TokenExpiredError, InvalidTokenError):
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="Token has expired."
        )

    stmt_token = select(RefreshTokenModel).where(
        RefreshTokenModel.token == refresh.refresh_token
    )
    result_token = await db.execute(stmt_token)
    refresh_token_record = result_token.scalars().first()

    if not refresh_token_record:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Refresh token not found."
        )

    stmt_user = select(UserModel).where(UserModel.id == user_id)
    result_user = await db.execute(stmt_user)
    user = result_user.scalars().first()

    if not user:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail="User not found."
        )

    access_token = jwt_manager.create_access_token({"user_id": user.id})

    return RefreshTokenResponseSchema(access_token=access_token)
