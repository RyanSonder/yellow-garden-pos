import json
from datetime import datetime
from decimal import Decimal

from sqlalchemy import (
    DECIMAL,
    DateTime,
    ForeignKey,
    Integer,
    String,
    Text,
    func,
)
from sqlalchemy.orm import DeclarativeBase, Mapped, mapped_column


class Base(DeclarativeBase):
    pass


class Employee(Base):
    __tablename__ = "employees"

    id: Mapped[int] = mapped_column(
        Integer,
        primary_key=True,
    )

    username: Mapped[str] = mapped_column(
        String(50),
        unique=True,
        nullable=False,
    )

    password_hash: Mapped[str] = mapped_column(
        nullable=False,
    )

    role: Mapped[str] = mapped_column(
        String(20),
        default="employee",
    )

    is_active: Mapped[bool] = mapped_column(
        default=True,
        nullable=False,
        server_default="true",
    )

    created_at: Mapped[datetime] = mapped_column(
        DateTime,
        server_default=func.now(),
        nullable=False,
    )


class AuditLog(Base):
    __tablename__ = "audit_logs"

    id: Mapped[int] = mapped_column(
        Integer,
        primary_key=True,
    )

    employee_id: Mapped[int | None] = mapped_column(
        ForeignKey("employees.id"),
        nullable=True,
    )

    action: Mapped[str] = mapped_column(
        String(100),
        nullable=False,
    )

    entity_type: Mapped[str] = mapped_column(
        String(50),
        nullable=False,
    )

    entity_id: Mapped[int | None] = mapped_column(
        Integer,
        nullable=True,
    )

    details: Mapped[str | None] = mapped_column(
        Text,
        nullable=True,
    )

    created_at: Mapped[datetime] = mapped_column(
        DateTime,
        server_default=func.now(),
        nullable=False,
    )


class Product(Base):
    __tablename__ = "products"

    id: Mapped[int] = mapped_column(
        Integer,
        primary_key=True,
    )

    name: Mapped[str] = mapped_column(
        String(100),
        nullable=False,
    )

    type: Mapped[str] = mapped_column(
        String(50),
        nullable=False,
    )

    buy_cost: Mapped[Decimal] = mapped_column(
        DECIMAL(10, 2),
        nullable=False,
    )

    sell_cost: Mapped[Decimal] = mapped_column(
        DECIMAL(10, 2),
        nullable=False,
    )

    desired_quantity: Mapped[Decimal] = mapped_column(
        DECIMAL(10, 3),
        nullable=False,
        default=Decimal("0.000"),
    )

    is_active: Mapped[bool] = mapped_column(
        default=True,
        nullable=False,
        server_default="true",
    )

    created_at: Mapped[datetime] = mapped_column(
        DateTime,
        server_default=func.now(),
        nullable=False,
    )


class Deposit(Base):
    __tablename__ = "deposits"

    id: Mapped[int] = mapped_column(
        Integer,
        primary_key=True,
    )

    # NULL means Store-owned inventory.
    employee_id: Mapped[int | None] = mapped_column(
        ForeignKey("employees.id"),
        nullable=True,
    )

    product_id: Mapped[int] = mapped_column(
        ForeignKey("products.id"),
        nullable=False,
    )

    quantity: Mapped[Decimal] = mapped_column(
        DECIMAL(10, 3),
        nullable=False,
    )

    quantity_remaining: Mapped[Decimal] = mapped_column(
        DECIMAL(10, 3),
        nullable=False,
    )

    deposited_at: Mapped[datetime] = mapped_column(
        DateTime,
        server_default=func.now(),
        nullable=False,
    )


class Sale(Base):
    __tablename__ = "sales"

    id: Mapped[int] = mapped_column(
        Integer,
        primary_key=True,
    )

    product_id: Mapped[int] = mapped_column(
        ForeignKey("products.id"),
        nullable=False,
    )

    quantity: Mapped[Decimal] = mapped_column(
        DECIMAL(10, 3),
        nullable=False,
    )

    sold_at: Mapped[datetime] = mapped_column(
        DateTime,
        server_default=func.now(),
        nullable=False,
    )


class PayoutAllocation(Base):
    __tablename__ = "payout_allocations"

    id: Mapped[int] = mapped_column(
        Integer,
        primary_key=True,
    )

    sale_id: Mapped[int] = mapped_column(
        ForeignKey("sales.id"),
        nullable=False,
    )

    deposit_id: Mapped[int] = mapped_column(
        ForeignKey("deposits.id"),
        nullable=False,
    )

    employee_id: Mapped[int] = mapped_column(
        ForeignKey("employees.id"),
        nullable=False,
    )

    quantity: Mapped[Decimal] = mapped_column(
        DECIMAL(10, 3),
        nullable=False,
    )

    payout_amount: Mapped[Decimal] = mapped_column(
        DECIMAL(10, 2),
        nullable=False,
    )

    paid_amount: Mapped[Decimal] = mapped_column(
        DECIMAL(10, 2),
        nullable=False,
        default=Decimal("0.00"),
    )

    created_at: Mapped[datetime] = mapped_column(
        DateTime,
        server_default=func.now(),
        nullable=False,
    )

    paid_at: Mapped[datetime | None] = mapped_column(
        DateTime,
        nullable=True,
    )


class PayoutPayment(Base):
    __tablename__ = "payout_payments"

    id: Mapped[int] = mapped_column(
        Integer,
        primary_key=True,
    )

    employee_id: Mapped[int] = mapped_column(
        ForeignKey("employees.id"),
        nullable=False,
    )

    amount: Mapped[Decimal] = mapped_column(
        DECIMAL(10, 2),
        nullable=False,
    )

    paid_at: Mapped[datetime] = mapped_column(
        DateTime,
        server_default=func.now(),
        nullable=False,
    )


class InventoryAdjustment(Base):
    __tablename__ = "inventory_adjustments"

    id: Mapped[int] = mapped_column(
        Integer,
        primary_key=True,
    )

    product_id: Mapped[int] = mapped_column(
        ForeignKey("products.id"),
        nullable=False,
    )

    manager_id: Mapped[int] = mapped_column(
        ForeignKey("employees.id"),
        nullable=False,
    )

    pos_quantity_before: Mapped[Decimal] = mapped_column(
        DECIMAL(10, 3),
        nullable=False,
    )

    physical_quantity: Mapped[Decimal] = mapped_column(
        DECIMAL(10, 3),
        nullable=False,
    )

    quantity_change: Mapped[Decimal] = mapped_column(
        DECIMAL(10, 3),
        nullable=False,
    )

    reason: Mapped[str] = mapped_column(
        Text,
        nullable=False,
    )

    created_at: Mapped[datetime] = mapped_column(
        DateTime,
        server_default=func.now(),
        nullable=False,
    )


class InventoryAdjustmentAllocation(Base):
    __tablename__ = "inventory_adjustment_allocations"

    id: Mapped[int] = mapped_column(
        Integer,
        primary_key=True,
    )

    adjustment_id: Mapped[int] = mapped_column(
        ForeignKey(
            "inventory_adjustments.id",
            ondelete="CASCADE",
        ),
        nullable=False,
    )

    deposit_id: Mapped[int] = mapped_column(
        ForeignKey("deposits.id"),
        nullable=False,
    )

    employee_id: Mapped[int | None] = mapped_column(
        ForeignKey("employees.id"),
        nullable=True,
    )

    quantity: Mapped[Decimal] = mapped_column(
        DECIMAL(10, 3),
        nullable=False,
    )

    created_at: Mapped[datetime] = mapped_column(
        DateTime,
        server_default=func.now(),
        nullable=False,
    )