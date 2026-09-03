from decimal import Decimal

from app.database import SessionLocal
from app.models import Employee, Ingredient, Deposit, PayoutAllocation
from app.fifo import process_sale


with SessionLocal() as db:

    # Create test employees
    bob = Employee(username="bob_test", password_hash="test")
    alice = Employee(username="alice_test", password_hash="test")

    db.add_all([bob, alice])
    db.flush()

    # Create ingredient
    tomatoes = Ingredient(
        name="Tomatoes",
        buy_cost=Decimal("2.00"),
        sell_cost=Decimal("3.50")
    )

    db.add(tomatoes)
    db.flush()

    # Deposits
    db.add(Deposit(
        employee_id=bob.id,
        ingredient_id=tomatoes.id,
        quantity=Decimal("10"),
        quantity_remaining=Decimal("10")
    ))

    db.add(Deposit(
        employee_id=alice.id,
        ingredient_id=tomatoes.id,
        quantity=Decimal("20"),
        quantity_remaining=Decimal("20")
    ))

    db.commit()

    # Sell 15 tomatoes
    sale = process_sale(
        db,
        tomatoes.id,
        Decimal("15")
    )

    allocations = db.query(PayoutAllocation).filter(
        PayoutAllocation.sale_id == sale.id
    ).all()

    for allocation in allocations:
        print(
            f"Employee {allocation.employee_id}: "
            f"{allocation.quantity} units -> "
            f"${allocation.payout_amount}"
        )