import json

from fastapi.testclient import TestClient
from pwdlib import PasswordHash

from app.database import SessionLocal
from app.main import app
from app.models import AuditLog, Employee, Product

USERNAME = "audit_log_test_user"
PASSWORD = "StrongPass123!"


def cleanup():
    with SessionLocal() as db:
        employee = db.query(Employee).filter(
            Employee.username == USERNAME
        ).first()

        if employee:
            db.query(AuditLog).filter(
                AuditLog.employee_id == employee.id
            ).delete(synchronize_session=False)
            db.query(Product).filter(
                Product.name == "Audit Product Test"
            ).delete(synchronize_session=False)
            db.query(Employee).filter(
                Employee.id == employee.id
            ).delete(synchronize_session=False)
            db.commit()
            return

        db.query(Product).filter(
            Product.name == "Audit Product Test"
        ).delete(synchronize_session=False)
        db.commit()


def test_audit_log_records_product_actions():
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

    create_response = client.post(
        "/products",
        params={
            "name": "Audit Product Test",
            "type": "fruit",
            "buy_cost": "1.25",
            "sell_cost": "2.75",
            "desired_quantity": "12",
        },
        headers=headers,
    )
    assert create_response.status_code == 200
    product_id = create_response.json()["id"]

    archive_response = client.delete(
        f"/products/{product_id}",
        headers=headers,
    )
    assert archive_response.status_code == 200

    audit_response = client.get(
        "/audit-log",
        headers=headers,
    )
    assert audit_response.status_code == 200
    entries = audit_response.json()
    assert any(
        entry.get("entity_type") == "product"
        and entry.get("action") in {"create_product", "archive_product"}
        and str(entry.get("entity_id")) == str(product_id)
        for entry in entries
    )

    cleanup()
