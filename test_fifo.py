from decimal import Decimal

from app.database import SessionLocal
from app.models import (
    AuditLog,
    Deposit,
    Employee,
    InventoryAdjustment,
    InventoryAdjustmentAllocation,
    PayoutAllocation,
    PayoutPayment,
    Product,
    Sale,
)
from app.fifo import process_sale


with SessionLocal() as db:
    target_employees = ["bob_test", "alice_test"]
    employee_ids = [
        employee.id
        for employee in db.query(Employee)
        .filter(Employee.username.in_(target_employees))
        .all()
    ]
    product_ids = [
        product.id
        for product in db.query(Product)
        .filter(Product.name == "Tomatoes", Product.type == "other")
        .all()
    ]

    sale_ids = [
        sale.id
        for sale in db.query(Sale)
        .filter(Sale.product_id.in_(product_ids))
        .all()
    ]

    if sale_ids:
        db.query(PayoutAllocation).filter(
            PayoutAllocation.sale_id.in_(sale_ids)
        ).delete(synchronize_session=False)

    deposit_ids = [
        deposit.id
        for deposit in db.query(Deposit)
        .filter(
            (Deposit.product_id.in_(product_ids)) |
            (Deposit.employee_id.in_(employee_ids))
        )
        .all()
    ]

    if deposit_ids:
        db.query(InventoryAdjustmentAllocation).filter(
            InventoryAdjustmentAllocation.deposit_id.in_(deposit_ids)
        ).delete(synchronize_session=False)
        db.query(PayoutAllocation).filter(
            PayoutAllocation.deposit_id.in_(deposit_ids)
        ).delete(synchronize_session=False)
        db.query(Deposit).filter(
            Deposit.id.in_(deposit_ids)
        ).delete(synchronize_session=False)

    if employee_ids:
        db.query(PayoutPayment).filter(
            PayoutPayment.employee_id.in_(employee_ids)
        ).delete(synchronize_session=False)
        db.query(InventoryAdjustment).filter(
            InventoryAdjustment.manager_id.in_(employee_ids)
        ).delete(synchronize_session=False)
        db.query(AuditLog).filter(
            AuditLog.employee_id.in_(employee_ids)
        ).delete(synchronize_session=False)
        db.query(Employee).filter(
            Employee.id.in_(employee_ids)
        ).delete(synchronize_session=False)

    if sale_ids:
        db.query(Sale).filter(
            Sale.id.in_(sale_ids)
        ).delete(synchronize_session=False)

    if product_ids:
        db.query(Product).filter(
            Product.id.in_(product_ids)
        ).delete(synchronize_session=False)

    db.commit()

    # Create test employees
    bob = Employee(username="bob_test", password_hash="test")
    alice = Employee(username="alice_test", password_hash="test")

    db.add_all([bob, alice])
    db.flush()

    # Create product
    tomatoes = Product(
        name="Tomatoes",
        type="other",
        buy_cost=Decimal("2.00"),
        sell_cost=Decimal("3.50")
    )

    db.add(tomatoes)
    db.flush()

    # Deposits
    db.add(Deposit(
        employee_id=bob.id,
        product_id=tomatoes.id,
        quantity=Decimal("10"),
        quantity_remaining=Decimal("10")
    ))

    db.add(Deposit(
        employee_id=alice.id,
        product_id=tomatoes.id,
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

    db.query(PayoutAllocation).filter(
        PayoutAllocation.sale_id == sale.id
    ).delete(synchronize_session=False)
    db.query(Deposit).filter(
        Deposit.product_id == tomatoes.id
    ).delete(synchronize_session=False)
    db.query(Sale).filter(
        Sale.id == sale.id
    ).delete(synchronize_session=False)
    db.delete(tomatoes)
    db.delete(bob)
    db.delete(alice)
    db.commit()