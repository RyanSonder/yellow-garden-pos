from datetime import datetime, timedelta, timezone
from decimal import Decimal

import jwt
from fastapi import APIRouter, Depends, HTTPException
from pydantic import BaseModel, Field
from pwdlib import PasswordHash
from sqlalchemy import func, select
from sqlalchemy.orm import Session

from .auth import get_current_user, require_manager
from .database import SessionLocal
from .fifo import process_sale
from .models import (
    Deposit,
    Employee,
    Ingredient,
    PayoutAllocation,
    PayoutPayment,
    Sale,
    InventoryAdjustment,
    InventoryAdjustmentAllocation,
)


router = APIRouter()

password_hash = PasswordHash.recommended()

SECRET_KEY = "change-this-later"
ALGORITHM = "HS256"


# ---------------------------------------------------------
# REQUEST MODELS
# ---------------------------------------------------------

class IngredientBulkUpdate(BaseModel):
    id: int
    name: str
    buy_cost: Decimal
    sell_cost: Decimal
    desired_quantity: Decimal


class AdminEmployeeUpdate(BaseModel):
    role: str | None = None
    password: str | None = None


class ReconcileAllocation(BaseModel):
    deposit_id: int
    quantity: Decimal


class InventoryReconcile(BaseModel):
    ingredient_id: int
    physical_quantity: Decimal
    reason: str
    employee_allocations: list[ReconcileAllocation] = Field(
        default_factory=list
    )


# ---------------------------------------------------------
# DATABASE
# ---------------------------------------------------------

def get_db():
    db = SessionLocal()
    try:
        yield db
    finally:
        db.close()


# ---------------------------------------------------------
# PERMISSIONS
# ---------------------------------------------------------

def require_admin(
    current_user: Employee = Depends(get_current_user),
):
    if current_user.role != "admin":
        raise HTTPException(
            status_code=403,
            detail="Admin access required",
        )

    return current_user


def require_manager_or_admin(
    current_user: Employee = Depends(get_current_user),
):
    if current_user.role not in ("manager", "admin"):
        raise HTTPException(
            status_code=403,
            detail="Manager or admin access required",
        )

    return current_user


# ---------------------------------------------------------
# EMPLOYEES
# ---------------------------------------------------------

@router.post("/employees")
def create_employee(
    username: str,
    password: str,
    role: str = "employee",
    db: Session = Depends(get_db),
    current_user: Employee = Depends(require_manager_or_admin),
):
    allowed_roles = {"employee", "manager", "admin"}

    if role not in allowed_roles:
        raise HTTPException(
            status_code=400,
            detail="Invalid employee rank",
        )

    if not username.strip():
        raise HTTPException(
            status_code=400,
            detail="Username cannot be empty",
        )

    if not password.strip():
        raise HTTPException(
            status_code=400,
            detail="Password cannot be empty",
        )

    employee = Employee(
        username=username,
        password_hash=password_hash.hash(password),
        role=role,
    )

    try:
        db.add(employee)
        db.commit()
        db.refresh(employee)
    except Exception:
        db.rollback()
        raise

    return {
        "id": employee.id,
        "username": employee.username,
        "role": employee.role,
    }


# ---------------------------------------------------------
# ADMIN EMPLOYEE MANAGEMENT
# ---------------------------------------------------------

@router.get("/admin/employees")
def get_all_employees(
    db: Session = Depends(get_db),
    current_user: Employee = Depends(require_admin),
):
    employees = (
        db.query(Employee)
        .order_by(Employee.username)
        .all()
    )

    return [
        {
            "id": employee.id,
            "username": employee.username,
            "role": employee.role,
            "created_at": employee.created_at,
        }
        for employee in employees
    ]


@router.put("/admin/employees/{employee_id}")
def update_employee_as_admin(
    employee_id: int,
    update: AdminEmployeeUpdate,
    db: Session = Depends(get_db),
    current_user: Employee = Depends(require_admin),
):
    employee = db.get(Employee, employee_id)

    if not employee:
        raise HTTPException(
            status_code=404,
            detail="Employee not found",
        )

    if employee.id == current_user.id:
        if update.role is not None and update.role != "admin":
            raise HTTPException(
                status_code=400,
                detail="You cannot change your own rank",
            )

    if update.role is not None:
        allowed_roles = {
            "employee",
            "manager",
            "admin",
        }

        if update.role not in allowed_roles:
            raise HTTPException(
                status_code=400,
                detail="Invalid employee rank",
            )

        employee.role = update.role

    if update.password is not None:
        if not update.password.strip():
            raise HTTPException(
                status_code=400,
                detail="Password cannot be empty",
            )

        employee.password_hash = password_hash.hash(
            update.password
        )

    try:
        db.commit()
        db.refresh(employee)
    except Exception:
        db.rollback()
        raise

    return {
        "id": employee.id,
        "username": employee.username,
        "role": employee.role,
    }


# ---------------------------------------------------------
# LOGIN
# ---------------------------------------------------------

@router.post("/login")
def login(
    username: str,
    password: str,
    db: Session = Depends(get_db),
):
    employee = (
        db.query(Employee)
        .filter(Employee.username == username)
        .first()
    )

    if not employee or not password_hash.verify(
        password,
        employee.password_hash,
    ):
        raise HTTPException(
            status_code=401,
            detail="Invalid username or password",
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
        "token_type": "bearer",
    }


# ---------------------------------------------------------
# CURRENT USER
# ---------------------------------------------------------

@router.get("/me")
def get_me(
    current_user: Employee = Depends(get_current_user),
):
    return {
        "id": current_user.id,
        "username": current_user.username,
        "role": current_user.role,
    }


# ---------------------------------------------------------
# INGREDIENTS
# ---------------------------------------------------------

@router.post("/ingredients")
def create_ingredient(
    name: str,
    buy_cost: Decimal,
    sell_cost: Decimal,
    desired_quantity: Decimal = Decimal("0.000"),
    db: Session = Depends(get_db),
    current_user: Employee = Depends(require_manager_or_admin),
):
    if buy_cost < 0:
        raise HTTPException(
            status_code=400,
            detail="Buy cost cannot be negative",
        )

    if sell_cost < 0:
        raise HTTPException(
            status_code=400,
            detail="Sell cost cannot be negative",
        )

    if desired_quantity < 0:
        raise HTTPException(
            status_code=400,
            detail="Desired quantity cannot be negative",
        )

    ingredient = Ingredient(
        name=name,
        buy_cost=buy_cost,
        sell_cost=sell_cost,
        desired_quantity=desired_quantity,
    )

    try:
        db.add(ingredient)
        db.commit()
        db.refresh(ingredient)
    except Exception:
        db.rollback()
        raise

    return ingredient


@router.get("/ingredients")
def get_ingredients(
    db: Session = Depends(get_db),
    current_user: Employee = Depends(get_current_user),
):
    return (
        db.query(Ingredient)
        .order_by(Ingredient.name)
        .all()
    )


# IMPORTANT:
# This route must come BEFORE /ingredients/{ingredient_id}
# so "bulk-update" is not interpreted as an ingredient ID.
@router.put("/ingredients/bulk-update")
def bulk_update_ingredients(
    updates: list[IngredientBulkUpdate],
    db: Session = Depends(get_db),
    current_user: Employee = Depends(require_manager_or_admin),
):
    if not updates:
        return {
            "message": "No ingredients to update",
            "updated": 0,
        }

    ingredient_ids = [update.id for update in updates]

    if len(ingredient_ids) != len(set(ingredient_ids)):
        raise HTTPException(
            status_code=400,
            detail="Duplicate ingredient IDs were submitted",
        )

    ingredients = (
        db.query(Ingredient)
        .filter(Ingredient.id.in_(ingredient_ids))
        .all()
    )

    ingredients_by_id = {
        ingredient.id: ingredient
        for ingredient in ingredients
    }

    if len(ingredients_by_id) != len(ingredient_ids):
        raise HTTPException(
            status_code=404,
            detail="One or more ingredients were not found",
        )

    for update in updates:
        if update.buy_cost < 0:
            raise HTTPException(
                status_code=400,
                detail=f"Buy cost cannot be negative for {update.name}",
            )

        if update.sell_cost < 0:
            raise HTTPException(
                status_code=400,
                detail=f"Sell cost cannot be negative for {update.name}",
            )

        if update.desired_quantity < 0:
            raise HTTPException(
                status_code=400,
                detail=(
                    f"Desired quantity cannot be negative "
                    f"for {update.name}"
                ),
            )

    try:
        for update in updates:
            ingredient = ingredients_by_id[update.id]

            ingredient.name = update.name
            ingredient.buy_cost = update.buy_cost
            ingredient.sell_cost = update.sell_cost
            ingredient.desired_quantity = update.desired_quantity

        db.commit()

        for ingredient in ingredients:
            db.refresh(ingredient)

    except Exception:
        db.rollback()
        raise

    return {
        "message": "Ingredients updated successfully",
        "updated": len(updates),
    }


@router.put("/ingredients/{ingredient_id}")
def update_ingredient(
    ingredient_id: int,
    name: str,
    buy_cost: Decimal,
    sell_cost: Decimal,
    desired_quantity: Decimal = Decimal("0.000"),
    db: Session = Depends(get_db),
    current_user: Employee = Depends(require_manager_or_admin),
):
    ingredient = db.get(Ingredient, ingredient_id)

    if not ingredient:
        raise HTTPException(
            status_code=404,
            detail="Ingredient not found",
        )

    if buy_cost < 0:
        raise HTTPException(
            status_code=400,
            detail="Buy cost cannot be negative",
        )

    if sell_cost < 0:
        raise HTTPException(
            status_code=400,
            detail="Sell cost cannot be negative",
        )

    if desired_quantity < 0:
        raise HTTPException(
            status_code=400,
            detail="Desired quantity cannot be negative",
        )

    ingredient.name = name
    ingredient.buy_cost = buy_cost
    ingredient.sell_cost = sell_cost
    ingredient.desired_quantity = desired_quantity

    try:
        db.commit()
        db.refresh(ingredient)
    except Exception:
        db.rollback()
        raise

    return ingredient


@router.delete("/ingredients/{ingredient_id}")
def delete_ingredient(
    ingredient_id: int,
    db: Session = Depends(get_db),
    current_user: Employee = Depends(require_manager_or_admin),
):
    ingredient = db.get(Ingredient, ingredient_id)

    if not ingredient:
        raise HTTPException(
            status_code=404,
            detail="Ingredient not found",
        )

    try:
        db.delete(ingredient)
        db.commit()
    except Exception:
        db.rollback()
        raise

    return {
        "message": "Ingredient deleted",
    }


# ---------------------------------------------------------
# DEPOSIT PREVIEW
# ---------------------------------------------------------

@router.get("/deposits/preview")
def preview_deposit(
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

    current_quantity = (
        db.query(
            func.coalesce(
                func.sum(Deposit.quantity_remaining),
                0,
            )
        )
        .filter(
            Deposit.ingredient_id == ingredient_id,
            Deposit.quantity_remaining > 0,
        )
        .scalar()
    )

    current_quantity = Decimal(str(current_quantity))

    desired_quantity = ingredient.desired_quantity

    space_available = max(
        desired_quantity - current_quantity,
        Decimal("0.000"),
    )

    employee_credit = min(
        quantity,
        space_available,
    )

    store_credit = quantity - employee_credit

    final_quantity = current_quantity + quantity

    return {
        "ingredient_id": ingredient.id,
        "ingredient_name": ingredient.name,
        "current_quantity": current_quantity,
        "desired_quantity": desired_quantity,
        "deposit_quantity": quantity,
        "employee_credit": employee_credit,
        "store_credit": store_credit,
        "final_quantity": final_quantity,
        "exceeds_desired": store_credit > 0,
    }


# ---------------------------------------------------------
# DEPOSITS
# ---------------------------------------------------------

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

    current_quantity = (
        db.query(
            func.coalesce(
                func.sum(Deposit.quantity_remaining),
                0,
            )
        )
        .filter(
            Deposit.ingredient_id == ingredient_id,
            Deposit.quantity_remaining > 0,
        )
        .scalar()
    )

    current_quantity = Decimal(str(current_quantity))

    space_available = max(
        ingredient.desired_quantity - current_quantity,
        Decimal("0.000"),
    )

    employee_credit = min(
        quantity,
        space_available,
    )

    store_credit = quantity - employee_credit

    try:
        if employee_credit > 0:
            db.add(
                Deposit(
                    employee_id=current_user.id,
                    ingredient_id=ingredient_id,
                    quantity=employee_credit,
                    quantity_remaining=employee_credit,
                )
            )

        if store_credit > 0:
            db.add(
                Deposit(
                    employee_id=None,
                    ingredient_id=ingredient_id,
                    quantity=store_credit,
                    quantity_remaining=store_credit,
                )
            )

        db.commit()

    except Exception:
        db.rollback()
        raise

    return {
        "ingredient_id": ingredient.id,
        "ingredient_name": ingredient.name,
        "deposited_quantity": quantity,
        "employee_credit": employee_credit,
        "store_credit": store_credit,
        "message": "Deposit recorded successfully",
    }


# ---------------------------------------------------------
# INVENTORY
# ---------------------------------------------------------

@router.get("/inventory")
def get_inventory(
    db: Session = Depends(get_db),
    current_user: Employee = Depends(get_current_user),
):
    ingredients = (
        db.query(Ingredient)
        .order_by(Ingredient.name)
        .all()
    )

    result = []

    for ingredient in ingredients:
        current_quantity = (
            db.query(
                func.coalesce(
                    func.sum(Deposit.quantity_remaining),
                    0,
                )
            )
            .filter(
                Deposit.ingredient_id == ingredient.id,
                Deposit.quantity_remaining > 0,
            )
            .scalar()
        )

        current_quantity = Decimal(str(current_quantity))

        desired_quantity = ingredient.desired_quantity

        needed_quantity = max(
            desired_quantity - current_quantity,
            Decimal("0.000"),
        )

        result.append({
            "ingredient_id": ingredient.id,
            "ingredient_name": ingredient.name,
            "current_quantity": current_quantity,
            "desired_quantity": desired_quantity,
            "needed_quantity": needed_quantity,
        })

    return result


# ---------------------------------------------------------
# RECONCILIATION
# ---------------------------------------------------------

@router.get("/reconcile")
def get_reconciliation_data(
    db: Session = Depends(get_db),
    current_user: Employee = Depends(require_manager_or_admin),
):
    ingredients = (
        db.query(Ingredient)
        .order_by(Ingredient.name)
        .all()
    )

    result = []

    for ingredient in ingredients:
        deposits = (
            db.query(Deposit, Employee)
            .outerjoin(
                Employee,
                Deposit.employee_id == Employee.id,
            )
            .filter(
                Deposit.ingredient_id == ingredient.id,
                Deposit.quantity_remaining > 0,
            )
            .order_by(
                Deposit.deposited_at,
                Deposit.id,
            )
            .all()
        )

        pos_quantity = sum(
            (
                deposit.quantity_remaining
                for deposit, _ in deposits
            ),
            Decimal("0.000"),
        )

        store_quantity = sum(
            (
                deposit.quantity_remaining
                for deposit, employee in deposits
                if employee is None
            ),
            Decimal("0.000"),
        )

        employee_lots = []

        for deposit, employee in deposits:
            if employee is None:
                continue

            employee_lots.append({
                "deposit_id": deposit.id,
                "employee_id": employee.id,
                "employee_name": employee.username,
                "quantity": deposit.quantity_remaining,
                "deposited_at": deposit.deposited_at,
            })

        result.append({
            "ingredient_id": ingredient.id,
            "ingredient_name": ingredient.name,
            "pos_quantity": pos_quantity,
            "desired_quantity": ingredient.desired_quantity,
            "store_quantity": store_quantity,
            "employee_lots": employee_lots,
        })

    return result


@router.post("/reconcile")
def reconcile_inventory(
    reconciliation: InventoryReconcile,
    db: Session = Depends(get_db),
    current_user: Employee = Depends(require_manager_or_admin),
):
    if reconciliation.physical_quantity < 0:
        raise HTTPException(
            status_code=400,
            detail="Physical quantity cannot be negative",
        )

    reason = reconciliation.reason.strip()

    if not reason:
        raise HTTPException(
            status_code=400,
            detail="A reason is required",
        )

    ingredient = (
        db.query(Ingredient)
        .filter(
            Ingredient.id == reconciliation.ingredient_id
        )
        .with_for_update()
        .first()
    )

    if not ingredient:
        raise HTTPException(
            status_code=404,
            detail="Ingredient not found",
        )

    deposits = (
        db.query(Deposit)
        .filter(
            Deposit.ingredient_id == ingredient.id,
            Deposit.quantity_remaining > 0,
        )
        .order_by(
            Deposit.deposited_at,
            Deposit.id,
        )
        .with_for_update()
        .all()
    )

    pos_quantity = sum(
        (
            deposit.quantity_remaining
            for deposit in deposits
        ),
        Decimal("0.000"),
    )

    difference = (
        reconciliation.physical_quantity
        - pos_quantity
    )

    if difference == 0:
        raise HTTPException(
            status_code=400,
            detail="Physical quantity already matches POS quantity",
        )

    adjustment = InventoryAdjustment(
        ingredient_id=ingredient.id,
        manager_id=current_user.id,
        pos_quantity_before=pos_quantity,
        physical_quantity=reconciliation.physical_quantity,
        quantity_change=difference,
        reason=reason,
    )

    db.add(adjustment)
    db.flush()

    # -----------------------------------------------------
    # PHYSICAL > POS
    #
    # Excess becomes Store-owned inventory.
    # -----------------------------------------------------

    if difference > 0:
        store_deposit = Deposit(
            employee_id=None,
            ingredient_id=ingredient.id,
            quantity=difference,
            quantity_remaining=difference,
        )

        db.add(store_deposit)
        db.flush()

        db.add(
            InventoryAdjustmentAllocation(
                adjustment_id=adjustment.id,
                deposit_id=store_deposit.id,
                employee_id=None,
                quantity=difference,
            )
        )

    # -----------------------------------------------------
    # PHYSICAL < POS
    #
    # Store inventory is removed first.
    # Employee inventory is reduced only when necessary.
    # -----------------------------------------------------

    else:
        shortage = -difference

        store_deposits = [
            deposit
            for deposit in deposits
            if deposit.employee_id is None
        ]

        store_available = sum(
            (
                deposit.quantity_remaining
                for deposit in store_deposits
            ),
            Decimal("0.000"),
        )

        store_to_remove = min(
            shortage,
            store_available,
        )

        remaining_store_reduction = store_to_remove

        for deposit in store_deposits:
            if remaining_store_reduction <= 0:
                break

            taken = min(
                deposit.quantity_remaining,
                remaining_store_reduction,
            )

            deposit.quantity_remaining -= taken
            remaining_store_reduction -= taken

            db.add(
                InventoryAdjustmentAllocation(
                    adjustment_id=adjustment.id,
                    deposit_id=deposit.id,
                    employee_id=None,
                    quantity=taken,
                )
            )

        employee_shortage = shortage - store_to_remove

        if employee_shortage > 0:
            if not reconciliation.employee_allocations:
                db.rollback()

                raise HTTPException(
                    status_code=400,
                    detail=(
                        f"Store inventory covers "
                        f"{store_to_remove:.3f}. "
                        f"Another "
                        f"{employee_shortage:.3f} "
                        f"must be assigned to employee inventory."
                    ),
                )

            deposit_ids = [
                allocation.deposit_id
                for allocation
                in reconciliation.employee_allocations
            ]

            if len(deposit_ids) != len(set(deposit_ids)):
                db.rollback()

                raise HTTPException(
                    status_code=400,
                    detail=(
                        "The same employee deposit "
                        "cannot be selected twice."
                    ),
                )

            selected_total = sum(
                (
                    allocation.quantity
                    for allocation
                    in reconciliation.employee_allocations
                ),
                Decimal("0.000"),
            )

            if selected_total != employee_shortage:
                db.rollback()

                raise HTTPException(
                    status_code=400,
                    detail=(
                        "Employee inventory reductions must "
                        "exactly cover the remaining shortage "
                        f"of {employee_shortage:.3f}."
                    ),
                )

            deposits_by_id = {
                deposit.id: deposit
                for deposit in deposits
            }

            for allocation in (
                reconciliation.employee_allocations
            ):
                if allocation.quantity <= 0:
                    db.rollback()

                    raise HTTPException(
                        status_code=400,
                        detail=(
                            "Employee reduction quantities "
                            "must be greater than zero."
                        ),
                    )

                deposit = deposits_by_id.get(
                    allocation.deposit_id
                )

                if not deposit:
                    db.rollback()

                    raise HTTPException(
                        status_code=400,
                        detail=(
                            "One of the selected deposits "
                            "does not belong to this ingredient."
                        ),
                    )

                if deposit.employee_id is None:
                    db.rollback()

                    raise HTTPException(
                        status_code=400,
                        detail=(
                            "Store inventory cannot be entered "
                            "as an employee reduction."
                        ),
                    )

                if (
                    allocation.quantity
                    > deposit.quantity_remaining
                ):
                    db.rollback()

                    raise HTTPException(
                        status_code=400,
                        detail=(
                            f"Cannot remove "
                            f"{allocation.quantity:.3f} "
                            f"from deposit #{deposit.id}. "
                            f"Only "
                            f"{deposit.quantity_remaining:.3f} "
                            f"is available."
                        ),
                    )

                deposit.quantity_remaining -= (
                    allocation.quantity
                )

                db.add(
                    InventoryAdjustmentAllocation(
                        adjustment_id=adjustment.id,
                        deposit_id=deposit.id,
                        employee_id=deposit.employee_id,
                        quantity=allocation.quantity,
                    )
                )

    try:
        db.commit()
        db.refresh(adjustment)

    except Exception:
        db.rollback()
        raise

    return {
        "adjustment_id": adjustment.id,
        "ingredient_id": ingredient.id,
        "ingredient_name": ingredient.name,
        "pos_quantity_before": pos_quantity,
        "physical_quantity": reconciliation.physical_quantity,
        "quantity_change": difference,
        "reason": reason,
        "message": "Inventory reconciled successfully",
    }


# ---------------------------------------------------------
# RECONCILIATION HISTORY
# ---------------------------------------------------------

@router.get("/reconcile/history")
def get_reconciliation_history(
    db: Session = Depends(get_db),
    current_user: Employee = Depends(require_manager_or_admin),
):
    try:
        adjustments = (
            db.query(InventoryAdjustment)
            .order_by(
                InventoryAdjustment.created_at.desc(),
                InventoryAdjustment.id.desc(),
            )
            .all()
        )

        result = []

        for adjustment in adjustments:
            ingredient = db.get(
                Ingredient,
                adjustment.ingredient_id,
            )

            manager = db.get(
                Employee,
                adjustment.manager_id,
            )

            allocations = (
                db.query(InventoryAdjustmentAllocation)
                .filter(
                    InventoryAdjustmentAllocation.adjustment_id
                    == adjustment.id
                )
                .order_by(
                    InventoryAdjustmentAllocation.id
                )
                .all()
            )

            allocation_result = []

            for allocation in allocations:
                employee_name = "Store"

                if allocation.employee_id is not None:
                    employee = db.get(
                        Employee,
                        allocation.employee_id,
                    )

                    if employee:
                        employee_name = employee.username

                allocation_result.append({
                    "deposit_id": allocation.deposit_id,
                    "employee_id": allocation.employee_id,
                    "employee_name": employee_name,
                    "quantity": allocation.quantity,
                })

            result.append({
                "id": adjustment.id,
                "ingredient_id": adjustment.ingredient_id,
                "ingredient_name": (
                    ingredient.name
                    if ingredient
                    else "Unknown Ingredient"
                ),
                "manager_id": adjustment.manager_id,
                "manager_name": (
                    manager.username
                    if manager
                    else "Unknown Manager"
                ),
                "pos_quantity_before": (
                    adjustment.pos_quantity_before
                ),
                "physical_quantity": (
                    adjustment.physical_quantity
                ),
                "quantity_change": (
                    adjustment.quantity_change
                ),
                "reason": adjustment.reason,
                "created_at": adjustment.created_at,
                "allocations": allocation_result,
            })

        return result

    except Exception as e:
        db.rollback()

        raise HTTPException(
            status_code=500,
            detail=f"Reconciliation history error: {str(e)}",
        )


# ---------------------------------------------------------
# OWNERSHIP - MANAGERS
# ---------------------------------------------------------

@router.get("/ownership")
def get_ownership(
    db: Session = Depends(get_db),
    current_user: Employee = Depends(require_manager_or_admin),
):
    deposits = (
        db.query(Deposit, Ingredient, Employee)
        .join(
            Ingredient,
            Deposit.ingredient_id == Ingredient.id,
        )
        .outerjoin(
            Employee,
            Deposit.employee_id == Employee.id,
        )
        .filter(
            Deposit.quantity_remaining > 0,
        )
        .order_by(
            Ingredient.name,
            Deposit.employee_id,
            Deposit.deposited_at,
            Deposit.id,
        )
        .all()
    )

    result = []
    store_totals = {}

    for deposit, ingredient, employee in deposits:

        if employee is None:
            if ingredient.id not in store_totals:
                store_totals[ingredient.id] = {
                    "ingredient_id": ingredient.id,
                    "ingredient_name": ingredient.name,
                    "owner_id": None,
                    "owner_name": "Store",
                    "quantity": Decimal("0.000"),
                    "credited_amount": None,
                    "store_value": Decimal("0.00"),
                    "deposited_at": None,
                }

            store_totals[ingredient.id]["quantity"] += (
                deposit.quantity_remaining
            )

            store_totals[ingredient.id]["store_value"] += (
                deposit.quantity_remaining
                * ingredient.buy_cost
            )

            continue

        credited_amount = (
            deposit.quantity_remaining
            * ingredient.buy_cost
        )

        result.append({
            "deposit_id": deposit.id,
            "ingredient_id": ingredient.id,
            "ingredient_name": ingredient.name,
            "owner_id": employee.id,
            "owner_name": employee.username,
            "quantity": deposit.quantity_remaining,
            "credited_amount": credited_amount,
            "store_value": None,
            "deposited_at": deposit.deposited_at,
        })

    result.extend(store_totals.values())

    result.sort(
        key=lambda item: (
            item["ingredient_name"].lower(),
            0 if item["owner_name"] == "Store" else 1,
            item["owner_name"].lower(),
            item["deposited_at"] or datetime.min,
            item.get("deposit_id") or 0,
        )
    )

    return result


# ---------------------------------------------------------
# MY INVENTORY
# ---------------------------------------------------------

@router.get("/my-inventory")
def get_my_inventory(
    db: Session = Depends(get_db),
    current_user: Employee = Depends(get_current_user),
):
    deposits = (
        db.query(Deposit, Ingredient)
        .join(
            Ingredient,
            Deposit.ingredient_id == Ingredient.id,
        )
        .filter(
            Deposit.employee_id == current_user.id,
            Deposit.quantity_remaining > 0,
        )
        .order_by(
            Ingredient.name,
            Deposit.deposited_at.desc(),
            Deposit.id.desc(),
        )
        .all()
    )

    result = []

    for deposit, ingredient in deposits:
        credited_amount = (
            deposit.quantity_remaining
            * ingredient.buy_cost
        )

        result.append({
            "deposit_id": deposit.id,
            "ingredient_id": ingredient.id,
            "ingredient_name": ingredient.name,
            "quantity": deposit.quantity_remaining,
            "credited_amount": credited_amount,
            "deposited_at": deposit.deposited_at,
        })

    return result


# ---------------------------------------------------------
# SALES
# ---------------------------------------------------------

@router.post("/sales")
def create_sale(
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

    try:
        sale = process_sale(
            db,
            ingredient_id,
            quantity,
        )
    except ValueError as e:
        db.rollback()

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
    current_user: Employee = Depends(require_manager_or_admin),
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
            > PayoutAllocation.paid_amount,
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
    current_user: Employee = Depends(require_manager_or_admin),
):
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
            payout.payout_amount
            - payout.paid_amount
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
            detail=(
                "Payment cannot exceed outstanding balance "
                f"of {outstanding:.2f}g"
            ),
        )

    remaining_payment = amount

    paid_time = datetime.now(
        timezone.utc
    ).replace(tzinfo=None)

    for payout in payouts:
        if remaining_payment <= 0:
            break

        allocation_remaining = (
            payout.payout_amount
            - payout.paid_amount
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

    try:
        db.add(payment)
        db.commit()
    except Exception:
        db.rollback()
        raise

    return {
        "employee_id": employee_id,
        "employee_name": employee.username,
        "amount_paid": amount,
        "remaining_balance": outstanding - amount,
        "message": "Employee paid successfully",
    }


# ---------------------------------------------------------
# PAYOUT HISTORY
# ---------------------------------------------------------

@router.get("/payout-history")
def get_payout_history(
    db: Session = Depends(get_db),
    current_user: Employee = Depends(require_manager_or_admin),
):
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
        .order_by(
            PayoutPayment.paid_at.desc()
        )
        .all()
    )

    return payments