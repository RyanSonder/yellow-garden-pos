import jwt
from fastapi import Depends, HTTPException
from fastapi.security import HTTPBearer, HTTPAuthorizationCredentials
from sqlalchemy.orm import Session

from .database import SessionLocal
from .models import Employee

SECRET_KEY = "change-this-later"
ALGORITHM = "HS256"

security = HTTPBearer()


def get_db():
    db = SessionLocal()
    try:
        yield db
    finally:
        db.close()


def get_current_user(
    credentials: HTTPAuthorizationCredentials = Depends(security),
    db: Session = Depends(get_db),
):
    try:
        payload = jwt.decode(
            credentials.credentials,
            SECRET_KEY,
            algorithms=[ALGORITHM],
        )

        employee_id = int(payload["sub"])

    except (jwt.InvalidTokenError, KeyError, ValueError):
        raise HTTPException(
            status_code=401,
            detail="Invalid or expired token",
        )

    employee = db.get(Employee, employee_id)

    if not employee:
        raise HTTPException(
            status_code=401,
            detail="User not found",
        )

    return employee

def require_manager(
    current_user: Employee = Depends(get_current_user),
):
    if current_user.role != "manager":
        raise HTTPException(
            status_code=403,
            detail="Manager access required",
        )

    return current_user