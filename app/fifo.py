from decimal import Decimal
from sqlalchemy import select
from sqlalchemy.orm import Session

from .models import Deposit, Sale, PayoutAllocation, Ingredient


def process_sale(db: Session, ingredient_id: int, quantity: Decimal):
    if quantity <= 0:
        raise ValueError("Quantity must be greater than zero")

    ingredient = db.get(Ingredient, ingredient_id)

    if not ingredient:
        raise ValueError("Ingredient not found")

    deposits = db.scalars(
        select(Deposit)
        .where(
            Deposit.ingredient_id == ingredient_id,
            Deposit.quantity_remaining > 0,
        )
        .order_by(Deposit.deposited_at, Deposit.id)
        .with_for_update()
    ).all()

    available = sum(
        (d.quantity_remaining for d in deposits),
        Decimal("0")
    )

    if available < quantity:
        raise ValueError("Not enough inventory")

    sale = Sale(
        ingredient_id=ingredient_id,
        quantity=quantity
    )
    db.add(sale)
    db.flush()

    remaining = quantity

    for deposit in deposits:
        if remaining <= 0:
            break

        taken = min(deposit.quantity_remaining, remaining)
        payout = taken * ingredient.buy_cost

        db.add(PayoutAllocation(
            sale_id=sale.id,
            deposit_id=deposit.id,
            employee_id=deposit.employee_id,
            quantity=taken,
            payout_amount=payout,
        ))

        deposit.quantity_remaining -= taken
        remaining -= taken

    db.commit()

    return sale