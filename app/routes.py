from datetime import datetime, timedelta, timezone
from decimal import Decimal

import jwt
from fastapi import APIRouter, Depends, HTTPException
from pydantic import BaseModel, Field
from pwdlib import PasswordHash
from sqlalchemy import func
from sqlalchemy.orm import Session

from .auth import get_current_user
from .database import SessionLocal
from .fifo import process_sale
from .models import (
    Deposit,
    Employee,
    Product,
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


class ProductBulkUpdate(BaseModel):
    id: int
    name: str
    type: str
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
    product_id: int
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
    if current_user.role not in ("admin", "senior_admin"):
        raise HTTPException(
            status_code=403,
            detail="Admin access required",
        )

    return current_user


def require_manager_or_admin(
    current_user: Employee = Depends(get_current_user),
):
    if current_user.role not in (
        "manager",
        "admin",
        "senior_admin",
    ):
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
    allowed_roles = {
        "employee",
        "manager",
        "admin",
        "senior_admin",
    }

    if role not in allowed_roles:
        raise HTTPException(
            status_code=400,
            detail="Invalid employee rank",
        )

    if (
        role == "senior_admin" and
        current_user.role != "senior_admin"
    ):
        raise HTTPException(
            status_code=403,
            detail="Only a senior admin can assign the senior admin role",
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
        if update.role is not None and update.role not in (
            "admin",
            "senior_admin",
        ):
            raise HTTPException(
                status_code=400,
                detail="You cannot change your own rank",
            )

    if update.role is not None:
        allowed_roles = {
            "employee",
            "manager",
            "admin",
            "senior_admin",
        }

        if update.role not in allowed_roles:
            raise HTTPException(
                status_code=400,
                detail="Invalid employee rank",
            )

        if (
            current_user.role != "senior_admin" and
            (
                (
                    employee.role == "senior_admin" and
                    update.role != employee.role
                ) or
                (
                    update.role == "senior_admin" and
                    employee.role != update.role
                )
            )
        ):
            raise HTTPException(
                status_code=403,
                detail="Only a senior admin can change the senior admin role",
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
            "exp": (
                datetime.now(timezone.utc)
                + timedelta(hours=8)
            ),
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
# PRODUCTS
# ---------------------------------------------------------


@router.post("/products")
def create_product(
    name: str,
    type: str,
    buy_cost: Decimal,
    sell_cost: Decimal,
    desired_quantity: Decimal = Decimal("0.000"),
    db: Session = Depends(get_db),
    current_user: Employee = Depends(require_manager_or_admin),
):
    name = name.strip()
    type = type.strip()

    if not name:
        raise HTTPException(
            status_code=400,
            detail="Product name cannot be empty",
        )

    if not type:
        raise HTTPException(
            status_code=400,
            detail="Product type cannot be empty",
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

    existing_product = (
        db.query(Product)
        .filter(
            Product.name == name,
            Product.type == type,
        )
        .first()
    )

    if existing_product:
        raise HTTPException(
            status_code=409,
            detail=(
                "A product with this name and type "
                "already exists"
            ),
        )

    product = Product(
        name=name,
        type=type,
        buy_cost=buy_cost,
        sell_cost=sell_cost,
        desired_quantity=desired_quantity,
    )

    try:
        db.add(product)
        db.commit()
        db.refresh(product)

    except Exception:
        db.rollback()
        raise

    return product


@router.get("/products")
def get_products(
    db: Session = Depends(get_db),
    current_user: Employee = Depends(get_current_user),
):
    return (
        db.query(Product)
        .order_by(
            Product.name,
            Product.type,
        )
        .all()
    )


@router.put("/products/bulk-update")
def bulk_update_products(
    updates: list[ProductBulkUpdate],
    db: Session = Depends(get_db),
    current_user: Employee = Depends(require_manager_or_admin),
):
    if not updates:
        return {
            "message": "No products to update",
            "updated": 0,
        }

    product_ids = [
        update.id
        for update in updates
    ]

    if len(product_ids) != len(set(product_ids)):
        raise HTTPException(
            status_code=400,
            detail="Duplicate product IDs were submitted",
        )

    products = (
        db.query(Product)
        .filter(Product.id.in_(product_ids))
        .all()
    )

    products_by_id = {
        product.id: product
        for product in products
    }

    if len(products_by_id) != len(product_ids):
        raise HTTPException(
            status_code=404,
            detail="One or more products were not found",
        )

    for update in updates:
        name = update.name.strip()
        type = update.type.strip()

        if not name:
            raise HTTPException(
                status_code=400,
                detail="Product name cannot be empty",
            )

        if not type:
            raise HTTPException(
                status_code=400,
                detail="Product type cannot be empty",
            )

        if update.buy_cost < 0:
            raise HTTPException(
                status_code=400,
                detail=(
                    f"Buy cost cannot be negative "
                    f"for {name}"
                ),
            )

        if update.sell_cost < 0:
            raise HTTPException(
                status_code=400,
                detail=(
                    f"Sell cost cannot be negative "
                    f"for {name}"
                ),
            )

        if update.desired_quantity < 0:
            raise HTTPException(
                status_code=400,
                detail=(
                    f"Desired quantity cannot be negative "
                    f"for {name}"
                ),
            )

        duplicate = (
            db.query(Product)
            .filter(
                Product.name == name,
                Product.type == type,
                Product.id != update.id,
            )
            .first()
        )

        if duplicate:
            raise HTTPException(
                status_code=409,
                detail=(
                    f"A product named '{name}' with "
                    f"type '{type}' already exists"
                ),
            )

    try:
        for update in updates:
            product = products_by_id[update.id]

            product.name = update.name.strip()
            product.type = update.type.strip()
            product.buy_cost = update.buy_cost
            product.sell_cost = update.sell_cost
            product.desired_quantity = update.desired_quantity

        db.commit()

        for product in products:
            db.refresh(product)

    except Exception:
        db.rollback()
        raise

    return {
        "message": "Products updated successfully",
        "updated": len(updates),
    }


@router.put("/products/{product_id}")
def update_product(
    product_id: int,
    name: str,
    type: str,
    buy_cost: Decimal,
    sell_cost: Decimal,
    desired_quantity: Decimal = Decimal("0.000"),
    db: Session = Depends(get_db),
    current_user: Employee = Depends(require_manager_or_admin),
):
    product = db.get(Product, product_id)

    if not product:
        raise HTTPException(
            status_code=404,
            detail="Product not found",
        )

    name = name.strip()
    type = type.strip()

    if not name:
        raise HTTPException(
            status_code=400,
            detail="Product name cannot be empty",
        )

    if not type:
        raise HTTPException(
            status_code=400,
            detail="Product type cannot be empty",
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

    duplicate = (
        db.query(Product)
        .filter(
            Product.name == name,
            Product.type == type,
            Product.id != product_id,
        )
        .first()
    )

    if duplicate:
        raise HTTPException(
            status_code=409,
            detail=(
                "A product with this name and type "
                "already exists"
            ),
        )

    product.name = name
    product.type = type
    product.buy_cost = buy_cost
    product.sell_cost = sell_cost
    product.desired_quantity = desired_quantity

    try:
        db.commit()
        db.refresh(product)

    except Exception:
        db.rollback()
        raise

    return product


@router.delete("/products/{product_id}")
def delete_product(
    product_id: int,
    db: Session = Depends(get_db),
    current_user: Employee = Depends(require_manager_or_admin),
):
    product = db.get(Product, product_id)

    if not product:
        raise HTTPException(
            status_code=404,
            detail="Product not found",
        )

    has_deposits = (
        db.query(Deposit.id)
        .filter(Deposit.product_id == product_id)
        .first()
        is not None
    )

    has_sales = (
        db.query(Sale.id)
        .filter(Sale.product_id == product_id)
        .first()
        is not None
    )

    has_adjustments = (
        db.query(InventoryAdjustment.id)
        .filter(
            InventoryAdjustment.product_id == product_id
        )
        .first()
        is not None
    )

    if has_deposits or has_sales or has_adjustments:
        raise HTTPException(
            status_code=409,
            detail=(
                "This product cannot be deleted because it has "
                "inventory or transaction history."
            ),
        )

    try:
        db.delete(product)
        db.commit()

    except Exception:
        db.rollback()
        raise

    return {
        "message": "Product deleted",
    }


# ---------------------------------------------------------
# DEPOSIT PREVIEW
# ---------------------------------------------------------


@router.get("/deposits/preview")
def preview_deposit(
    product_id: int,
    quantity: Decimal,
    db: Session = Depends(get_db),
    current_user: Employee = Depends(get_current_user),
):
    if quantity <= 0:
        raise HTTPException(
            status_code=400,
            detail="Quantity must be greater than zero",
        )

    product = db.get(Product, product_id)

    if not product:
        raise HTTPException(
            status_code=404,
            detail="Product not found",
        )

    current_quantity = (
        db.query(
            func.coalesce(
                func.sum(Deposit.quantity_remaining),
                0,
            )
        )
        .filter(
            Deposit.product_id == product_id,
            Deposit.quantity_remaining > 0,
        )
        .scalar()
    )

    current_quantity = Decimal(
        str(current_quantity)
    )

    desired_quantity = product.desired_quantity

    space_available = max(
        desired_quantity - current_quantity,
        Decimal("0.000"),
    )

    employee_credit = min(
        quantity,
        space_available,
    )

    store_credit = quantity - employee_credit

    final_quantity = (
        current_quantity + quantity
    )

    return {
        "product_id": product.id,
        "product_name": product.name,
        "product_type": product.type,
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
    product_id: int,
    quantity: Decimal,
    store_stock: bool = False,
    db: Session = Depends(get_db),
    current_user: Employee = Depends(get_current_user),
):
    if quantity <= 0:
        raise HTTPException(
            status_code=400,
            detail="Quantity must be greater than zero",
        )

    product = db.get(Product, product_id)

    if not product:
        raise HTTPException(
            status_code=404,
            detail="Product not found",
        )

    current_quantity = (
        db.query(
            func.coalesce(
                func.sum(Deposit.quantity_remaining),
                0,
            )
        )
        .filter(
            Deposit.product_id == product_id,
            Deposit.quantity_remaining > 0,
        )
        .scalar()
    )

    current_quantity = Decimal(
        str(current_quantity)
    )

    if store_stock:
        employee_credit = Decimal("0.000")
        store_credit = quantity
    else:
        space_available = max(
            product.desired_quantity - current_quantity,
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
                    product_id=product_id,
                    quantity=employee_credit,
                    quantity_remaining=employee_credit,
                )
            )

        if store_credit > 0:
            db.add(
                Deposit(
                    employee_id=None,
                    product_id=product_id,
                    quantity=store_credit,
                    quantity_remaining=store_credit,
                )
            )

        db.commit()

    except Exception:
        db.rollback()
        raise

    return {
        "product_id": product.id,
        "product_name": product.name,
        "product_type": product.type,
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
    products = (
        db.query(Product)
        .order_by(
            Product.name,
            Product.type,
        )
        .all()
    )

    result = []

    for product in products:
        current_quantity = (
            db.query(
                func.coalesce(
                    func.sum(Deposit.quantity_remaining),
                    0,
                )
            )
            .filter(
                Deposit.product_id == product.id,
                Deposit.quantity_remaining > 0,
            )
            .scalar()
        )

        current_quantity = Decimal(
            str(current_quantity)
        )

        desired_quantity = product.desired_quantity

        needed_quantity = max(
            desired_quantity - current_quantity,
            Decimal("0.000"),
        )

        result.append({
            "product_id": product.id,
            "product_name": product.name,
            "product_type": product.type,
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
    products = (
        db.query(Product)
        .order_by(
            Product.name,
            Product.type,
        )
        .all()
    )

    result = []

    for product in products:
        deposits = (
            db.query(Deposit, Employee)
            .outerjoin(
                Employee,
                Deposit.employee_id == Employee.id,
            )
            .filter(
                Deposit.product_id == product.id,
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
            "product_id": product.id,
            "product_name": product.name,
            "product_type": product.type,
            "pos_quantity": pos_quantity,
            "desired_quantity": product.desired_quantity,
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

    product = (
        db.query(Product)
        .filter(
            Product.id == reconciliation.product_id
        )
        .with_for_update()
        .first()
    )

    if not product:
        raise HTTPException(
            status_code=404,
            detail="Product not found",
        )

    deposits = (
        db.query(Deposit)
        .filter(
            Deposit.product_id == product.id,
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
            detail=(
                "Physical quantity already matches "
                "POS quantity"
            ),
        )

    adjustment = InventoryAdjustment(
        product_id=product.id,
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
            product_id=product.id,
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

        remaining_store_reduction = (
            store_to_remove
        )

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

        employee_shortage = (
            shortage - store_to_remove
        )

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
                        "Employee inventory reductions "
                        "must exactly cover the remaining "
                        "shortage of "
                        f"{employee_shortage:.3f}."
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
                            "does not belong to this product."
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
        "product_id": product.id,
        "product_name": product.name,
        "product_type": product.type,
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
            product = db.get(
                Product,
                adjustment.product_id,
            )

            manager = db.get(
                Employee,
                adjustment.manager_id,
            )

            allocations = (
                db.query(
                    InventoryAdjustmentAllocation
                )
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
                "product_id": adjustment.product_id,
                "product_name": (
                    product.name
                    if product
                    else "Unknown Product"
                ),
                "product_type": (
                    product.type
                    if product
                    else None
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
            detail=(
                "Reconciliation history error: "
                f"{str(e)}"
            ),
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
        db.query(Deposit, Product, Employee)
        .join(
            Product,
            Deposit.product_id == Product.id,
        )
        .outerjoin(
            Employee,
            Deposit.employee_id == Employee.id,
        )
        .filter(
            Deposit.quantity_remaining > 0,
        )
        .order_by(
            Product.name,
            Product.type,
            Deposit.employee_id,
            Deposit.deposited_at,
            Deposit.id,
        )
        .all()
    )

    result = []
    store_totals = {}

    for deposit, product, employee in deposits:

        if employee is None:
            if product.id not in store_totals:
                store_totals[product.id] = {
                    "product_id": product.id,
                    "product_name": product.name,
                    "product_type": product.type,
                    "owner_id": None,
                    "owner_name": "Store",
                    "quantity": Decimal("0.000"),
                    "credited_amount": None,
                    "store_value": Decimal("0.00"),
                    "deposited_at": None,
                }

            store_totals[product.id]["quantity"] += (
                deposit.quantity_remaining
            )

            store_totals[product.id]["store_value"] += (
                deposit.quantity_remaining
                * product.buy_cost
            )

            continue

        credited_amount = (
            deposit.quantity_remaining
            * product.buy_cost
        )

        result.append({
            "deposit_id": deposit.id,
            "product_id": product.id,
            "product_name": product.name,
            "product_type": product.type,
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
            item["product_name"].lower(),
            item["product_type"].lower(),
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
        db.query(Deposit, Product)
        .join(
            Product,
            Deposit.product_id == Product.id,
        )
        .filter(
            Deposit.employee_id == current_user.id,
            Deposit.quantity_remaining > 0,
        )
        .order_by(
            Product.name,
            Product.type,
            Deposit.deposited_at.desc(),
            Deposit.id.desc(),
        )
        .all()
    )

    result = []

    for deposit, product in deposits:
        credited_amount = (
            deposit.quantity_remaining
            * product.buy_cost
        )

        result.append({
            "deposit_id": deposit.id,
            "product_id": product.id,
            "product_name": product.name,
            "product_type": product.type,
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
    product_id: int,
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
            product_id,
            quantity,
        )

    except ValueError as e:
        db.rollback()

        raise HTTPException(
            status_code=400,
            detail=str(e),
        )

    product = db.get(
        Product,
        sale.product_id,
    )

    return {
        "sale_id": sale.id,
        "product_id": sale.product_id,
        "product_name": (
            product.name
            if product
            else None
        ),
        "product_type": (
            product.type
            if product
            else None
        ),
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
    employee = db.get(
        Employee,
        employee_id,
    )

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

    if amount != amount.quantize(
        Decimal("0.01")
    ):
        raise HTTPException(
            status_code=400,
            detail=(
                "Payment amount must have at most "
                "2 decimal places"
            ),
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
                f"of {outstanding:.2f}"
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