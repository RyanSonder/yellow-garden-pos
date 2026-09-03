import json
from decimal import Decimal

from sqlalchemy import select
from sqlalchemy.orm import Session

from .models import AuditLog, Deposit, Sale, PayoutAllocation, Product


def process_sale(
    db: Session,
    product_id: int,
    quantity: Decimal,
    employee_id: int | None = None,
):
    if quantity <= 0:
        raise ValueError("Quantity must be greater than zero")

    product = (
        db.query(Product)
        .filter(Product.id == product_id, Product.is_active.is_(True))
        .first()
    )

    if not product:
        raise ValueError("Product not found")

    deposits = db.scalars(
        select(Deposit)
        .where(
            Deposit.product_id == product_id,
            Deposit.quantity_remaining > 0,
        )
        .order_by(
            Deposit.deposited_at,
            Deposit.id,
        )
        .with_for_update()
    ).all()

    employee_deposits = [
        deposit
        for deposit in deposits
        if deposit.employee_id is not None
    ]

    store_deposits = [
        deposit
        for deposit in deposits
        if deposit.employee_id is None
    ]

    employee_available = sum(
        (
            deposit.quantity_remaining
            for deposit in employee_deposits
        ),
        Decimal("0.000"),
    )

    store_available = sum(
        (
            deposit.quantity_remaining
            for deposit in store_deposits
        ),
        Decimal("0.000"),
    )

    total_available = (
        employee_available
        + store_available
    )

    if total_available < quantity:
        raise ValueError("Not enough inventory")

    sale = Sale(
        product_id=product_id,
        quantity=quantity,
    )

    db.add(sale)
    db.flush()

    remaining = quantity

    # Employee-owned inventory is always used first.
    for deposit in employee_deposits:
        if remaining <= 0:
            break

        taken = min(
            deposit.quantity_remaining,
            remaining,
        )

        payout = taken * product.buy_cost

        db.add(
            PayoutAllocation(
                sale_id=sale.id,
                deposit_id=deposit.id,
                employee_id=deposit.employee_id,
                quantity=taken,
                payout_amount=payout,
            )
        )

        deposit.quantity_remaining -= taken
        remaining -= taken

    # Store inventory is used after employee inventory.
    for deposit in store_deposits:
        if remaining <= 0:
            break

        taken = min(
            deposit.quantity_remaining,
            remaining,
        )

        deposit.quantity_remaining -= taken
        remaining -= taken

    if employee_id is not None:
        db.add(
            AuditLog(
                employee_id=employee_id,
                action="create_sale",
                entity_type="sale",
                entity_id=sale.id,
                details=json.dumps({
                    "product_id": product.id,
                    "quantity": str(quantity),
                }),
            )
        )

    db.commit()

    return sale