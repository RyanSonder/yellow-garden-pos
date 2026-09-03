from datetime import datetime, timedelta, timezone
from decimal import Decimal

import jwt
from fastapi import HTTPException
from pwdlib import PasswordHash
from fastapi import APIRouter, Depends
from sqlalchemy import func
from sqlalchemy.orm import Session

from .database import SessionLocal
from .models import (
    Employee,
    Ingredient,
    Deposit,
    PayoutAllocation,
    Sale,
    PayoutPayment,
)
from .auth import get_current_user, require_manager
from .fifo import process_sale

router = APIRouter()
password_hash = PasswordHash.recommended()

SECRET_KEY = "change-this-later"
ALGORITHM = "HS256"


def get_db():
    db = SessionLocal()
    try:
        yield db
    finally:
        db.close()


@router.post("/employees")
def create_employee(
    username: str,
    password: str,
    role: str = "employee",
    db: Session = Depends(get_db),
    current_user: Employee = Depends(require_manager),
):
    employee = Employee(
        username=username,
        password_hash=password_hash.hash(password),
        role=role,
    )

    db.add(employee)
    db.commit()
    db.refresh(employee)

    return {
        "id": employee.id,
        "username": employee.username,
        "role": employee.role,
    }


@router.post("/login")
def login(
    username: str,
    password: str,
    db: Session = Depends(get_db),
):
    employee = db.query(Employee).filter(
        Employee.username == username
    ).first()

    if not employee or not password_hash.verify(
        password,
        employee.password_hash
    ):
        raise HTTPException(
            status_code=401,
            detail="Invalid username or password"
        )

    token = jwt.encode(
        {
            "sub": str(employee.id),
            "role": employee.role,
            "exp": datetime.now(timezone.utc) + timedelta(hours=8),
        },
        SECRET_KEY,
        algorithm=ALGORITHM,
    )

    return {
        "access_token": token,
        "token_type": "bearer"
    }


@router.get("/me")
def get_me(
    current_user: Employee = Depends(get_current_user),
):
    return {
        "id": current_user.id,
        "username": current_user.username,
        "role": current_user.role,
    }


@router.post("/ingredients")
def create_ingredient(
    name: str,
    buy_cost: Decimal,
    sell_cost: Decimal,
    db: Session = Depends(get_db),
    current_user: Employee = Depends(require_manager),
):
    ingredient = Ingredient(
        name=name,
        buy_cost=buy_cost,
        sell_cost=sell_cost,
    )

    db.add(ingredient)
    db.commit()
    db.refresh(ingredient)

    return ingredient


@router.get("/ingredients")
def get_ingredients(
    db: Session = Depends(get_db),
    current_user: Employee = Depends(get_current_user),
):
    return db.query(Ingredient).order_by(Ingredient.name).all()


@router.put("/ingredients/{ingredient_id}")
def update_ingredient(
    ingredient_id: int,
    name: str,
    buy_cost: Decimal,
    sell_cost: Decimal,
    db: Session = Depends(get_db),
    current_user: Employee = Depends(require_manager),
):
    ingredient = db.get(Ingredient, ingredient_id)

    if not ingredient:
        raise HTTPException(
            status_code=404,
            detail="Ingredient not found"
        )

    ingredient.name = name
    ingredient.buy_cost = buy_cost
    ingredient.sell_cost = sell_cost

    db.commit()
    db.refresh(ingredient)

    return ingredient


@router.delete("/ingredients/{ingredient_id}")
def delete_ingredient(
    ingredient_id: int,
    db: Session = Depends(get_db),
    current_user: Employee = Depends(require_manager),
):
    ingredient = db.get(Ingredient, ingredient_id)

    if not ingredient:
        raise HTTPException(
            status_code=404,
            detail="Ingredient not found"
        )

    db.delete(ingredient)
    db.commit()

    return {
        "message": "Ingredient deleted"
    }


@router.post("/deposits")
def create_deposit(
    ingredient_id: int,
    quantity: Decimal,
    db: Session = Depends(get_db),
    current_user: Employee = Depends(get_current_user),
):
    if quantity <= 0:
        raise HTTPException(
            status_code=400,
            detail="Quantity must be greater than zero",
        )

    ingredient = db.get(Ingredient, ingredient_id)

    if not ingredient:
        raise HTTPException(
            status_code=404,
            detail="Ingredient not found",
        )

    deposit = Deposit(
        employee_id=current_user.id,
        ingredient_id=ingredient_id,
        quantity=quantity,
        quantity_remaining=quantity,
    )

    db.add(deposit)
    db.commit()
    db.refresh(deposit)

    return deposit


@router.get("/inventory")
def get_inventory(
    db: Session = Depends(get_db),
    current_user: Employee = Depends(get_current_user),
):
    deposits = (
        db.query(Deposit)
        .filter(Deposit.quantity_remaining > 0)
        .order_by(Deposit.deposited_at, Deposit.id)
        .all()
    )

    result = []

    for deposit in deposits:
        employee = db.get(Employee, deposit.employee_id)
        ingredient = db.get(Ingredient, deposit.ingredient_id)

        result.append({
            "id": deposit.id,
            "employee_name": employee.username,
            "ingredient_name": ingredient.name,
            "quantity": deposit.quantity,
            "quantity_remaining": deposit.quantity_remaining,
            "deposited_at": deposit.deposited_at,
        })

    return result


@router.post("/sales")
def create_sale(
    ingredient_id: int,
    quantity: Decimal,
    db: Session = Depends(get_db),
    current_user: Employee = Depends(get_current_user),
):
    try:
        sale = process_sale(
            db,
            ingredient_id,
            quantity,
        )
    except ValueError as e:
        raise HTTPException(
            status_code=400,
            detail=str(e),
        )

    return {
        "sale_id": sale.id,
        "ingredient_id": sale.ingredient_id,
        "quantity": sale.quantity,
    }


# ---------------------------------------------------------
# PAYOUTS
# ---------------------------------------------------------

@router.get("/payouts")
def get_payouts(
    db: Session = Depends(get_db),
    current_user: Employee = Depends(require_manager),
):
    payouts = (
        db.query(
            Employee.id.label("employee_id"),
            Employee.username.label("employee_name"),
            func.sum(
                PayoutAllocation.payout_amount
                - PayoutAllocation.paid_amount
            ).label("amount_owed"),
        )
        .join(
            PayoutAllocation,
            PayoutAllocation.employee_id == Employee.id,
        )
        .filter(
            PayoutAllocation.payout_amount
            > PayoutAllocation.paid_amount
        )
        .group_by(
            Employee.id,
            Employee.username,
        )
        .order_by(Employee.username)
        .all()
    )

    return [
        {
            "employee_id": payout.employee_id,
            "employee_name": payout.employee_name,
            "amount_owed": payout.amount_owed,
        }
        for payout in payouts
    ]


@router.post("/payouts/{employee_id}/pay")
def pay_employee(
    employee_id: int,
    amount: Decimal,
    db: Session = Depends(get_db),
    current_user: Employee = Depends(require_manager),
):
    """
    Pays a specified amount to an employee.

    Payments are applied to the employee's oldest unpaid
    payout allocations first.
    """

    employee = db.get(Employee, employee_id)

    if not employee:
        raise HTTPException(
            status_code=404,
            detail="Employee not found",
        )

    if amount <= 0:
        raise HTTPException(
            status_code=400,
            detail="Payment amount must be greater than zero",
        )

    if amount != amount.quantize(Decimal("0.01")):
        raise HTTPException(
            status_code=400,
            detail="Payment amount must have at most 2 decimal places",
        )

    payouts = (
        db.query(PayoutAllocation)
        .filter(
            PayoutAllocation.employee_id == employee_id,
            PayoutAllocation.payout_amount
            > PayoutAllocation.paid_amount,
        )
        .order_by(
            PayoutAllocation.created_at,
            PayoutAllocation.id,
        )
        .with_for_update()
        .all()
    )

    outstanding = sum(
        (
            payout.payout_amount - payout.paid_amount
            for payout in payouts
        ),
        Decimal("0.00"),
    )

    if outstanding <= 0:
        raise HTTPException(
            status_code=400,
            detail="Employee has no unpaid balance",
        )

    if amount > outstanding:
        raise HTTPException(
            status_code=400,
            detail=f"Payment cannot exceed outstanding balance of ${outstanding:.2f}",
        )

    remaining_payment = amount
    paid_time = datetime.now(timezone.utc).replace(tzinfo=None)

    for payout in payouts:
        if remaining_payment <= 0:
            break

        allocation_remaining = (
            payout.payout_amount - payout.paid_amount
        )

        applied = min(
            remaining_payment,
            allocation_remaining,
        )

        payout.paid_amount += applied
        remaining_payment -= applied

        if payout.paid_amount >= payout.payout_amount:
            payout.paid_amount = payout.payout_amount
            payout.paid_at = paid_time

    payment = PayoutPayment(
        employee_id=employee_id,
        amount=amount,
    )

    db.add(payment)
    db.commit()

    return {
        "employee_id": employee_id,
        "employee_name": employee.username,
        "amount_paid": amount,
        "remaining_balance": outstanding - amount,
        "message": "Employee paid successfully",
    }


@router.get("/payout-history")
def get_payout_history(
    db: Session = Depends(get_db),
    current_user: Employee = Depends(require_manager),
):
    """
    Returns historical payments made to employees.
    """

    payments = (
        db.query(
            PayoutPayment.id,
            Employee.username.label("employee_name"),
            PayoutPayment.amount,
            PayoutPayment.paid_at,
        )
        .join(
            Employee,
            PayoutPayment.employee_id == Employee.id,
        )
        .order_by(PayoutPayment.paid_at.desc())
        .all()
    )

    return payments