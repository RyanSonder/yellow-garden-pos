from sqlalchemy import select
from app.database import SessionLocal
from app.models import Employee, Product, Deposit, Sale, PayoutAllocation

with SessionLocal() as db:
    tables = [
        Employee,
        Product,
        Deposit,
        Sale,
        PayoutAllocation,
    ]

    for table in tables:
        result = db.execute(select(table))
        print(f"{table.__tablename__}: OK ({len(result.scalars().all())} records)")