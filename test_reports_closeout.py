from decimal import Decimal

from fastapi.testclient import TestClient
from pwdlib import PasswordHash

from app.database import SessionLocal
from app.main import app
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

USERNAME = "closeout_test_user"
PASSWORD = "StrongPass123!"


def cleanup():
    with SessionLocal() as db:
        employee = db.query(Employee).filter(
            Employee.username == USERNAME
        ).first()

        product_ids = [
            product.id
            for product in db.query(Product)
            .filter(Product.name == "Closeout Product Test")
            .all()
        ]

        deposit_ids = [
            deposit.id
            for deposit in db.query(Deposit)
            .filter(Deposit.product_id.in_(product_ids))
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

        if employee:
            employee_ids = [employee.id]
            db.query(AuditLog).filter(
                AuditLog.employee_id.in_(employee_ids)
            ).delete(synchronize_session=False)
            db.query(PayoutPayment).filter(
                PayoutPayment.employee_id.in_(employee_ids)
            ).delete(synchronize_session=False)
            db.query(InventoryAdjustment).filter(
                InventoryAdjustment.manager_id.in_(employee_ids)
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


def test_closeout_report_summary():
    cleanup()

    with SessionLocal() as db:
        employee = Employee(
            username=USERNAME,
            password_hash=PasswordHash.recommended().hash(PASSWORD),
            role="admin",
        )
        db.add(employee)
        db.commit()
        db.refresh(employee)

    client = TestClient(app)
    login_response = client.post(
        "/login",
        json={"username": USERNAME, "password": PASSWORD},
    )
    assert login_response.status_code == 200
    token = login_response.json()["access_token"]
    headers = {"Authorization": f"Bearer {token}"}

    product_response = client.post(
        "/products",
        params={
            "name": "Closeout Product Test",
            "type": "fruit",
            "buy_cost": "1.25",
            "sell_cost": "2.75",
            "desired_quantity": "12",
        },
        headers=headers,
    )
    assert product_response.status_code == 200
    product_id = product_response.json()["id"]

    deposit_response = client.post(
        "/deposits",
        params={
            "product_id": product_id,
            "quantity": "5",
            "store_stock": "true",
        },
        headers=headers,
    )
    assert deposit_response.status_code == 200

    sale_response = client.post(
        "/sales",
        params={
            "product_id": product_id,
            "quantity": "2",
        },
        headers=headers,
    )
    assert sale_response.status_code == 200

    closeout_response = client.get(
        "/reports/closeout",
        headers=headers,
    )
    assert closeout_response.status_code == 200
    summary = closeout_response.json()
    assert summary["total_units_sold"] >= 2
    assert summary["gross_sales"] >= Decimal("5.50")
    assert summary["total_outstanding_payouts"] >= 0

    cleanup()
