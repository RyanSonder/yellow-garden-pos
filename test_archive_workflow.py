from fastapi.testclient import TestClient
from pwdlib import PasswordHash

from app.database import SessionLocal
from app.main import app
from app.models import AuditLog, Employee, Product


USERNAME = "archive_flow_test_user"
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
                Product.name == "Archive Product Test"
            ).delete(synchronize_session=False)
            db.query(Employee).filter(
                Employee.id == employee.id
            ).delete(synchronize_session=False)
            db.commit()
            return

        db.query(Product).filter(
            Product.name == "Archive Product Test"
        ).delete(synchronize_session=False)
        db.commit()


def test_archive_and_restore_product_flow():
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
            "name": "Archive Product Test",
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

    archived_response = client.get(
        "/products",
        params={"include_archived": True},
        headers=headers,
    )
    assert archived_response.status_code == 200
    archived_products = archived_response.json()
    assert any(
        item["id"] == product_id and item["is_active"] is False
        for item in archived_products
    )

    restore_response = client.post(
        f"/products/{product_id}/restore",
        headers=headers,
    )
    assert restore_response.status_code == 200

    active_response = client.get(
        "/products",
        headers=headers,
    )
    assert active_response.status_code == 200
    active_products = active_response.json()
    assert any(
        item["id"] == product_id and item["is_active"] is True
        for item in active_products
    )

    cleanup()
