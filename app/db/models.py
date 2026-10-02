"""Persistent PostgreSQL schema for the update training environment."""

from datetime import datetime
from typing import Any
from uuid import UUID, uuid4

from sqlalchemy import (
    BigInteger,
    CheckConstraint,
    DateTime,
    ForeignKey,
    ForeignKeyConstraint,
    Index,
    LargeBinary,
    String,
    Text,
    UniqueConstraint,
    func,
    text,
)
from sqlalchemy.dialects.postgresql import JSONB, UUID as PG_UUID
from sqlalchemy.orm import DeclarativeBase, Mapped, mapped_column


class Base(DeclarativeBase):
    pass


class Product(Base):
    __tablename__ = "products"

    id: Mapped[UUID] = mapped_column(PG_UUID(as_uuid=True), primary_key=True, default=uuid4)
    name: Mapped[str] = mapped_column(String(200), unique=True, nullable=False)
    target: Mapped[str] = mapped_column(String(200), nullable=False)
    created_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), server_default=func.now(), nullable=False
    )


class Package(Base):
    __tablename__ = "packages"
    __table_args__ = (
        UniqueConstraint("product_id", "version", "target", name="uq_packages_release"),
        UniqueConstraint("product_id", "id", name="uq_packages_product_id"),
        CheckConstraint("size_bytes >= 0", name="ck_packages_size_nonnegative"),
        CheckConstraint("status IN ('DRAFT', 'PUBLISHED')", name="ck_packages_status"),
        Index("ix_packages_product_status", "product_id", "status"),
    )

    id: Mapped[UUID] = mapped_column(PG_UUID(as_uuid=True), primary_key=True, default=uuid4)
    product_id: Mapped[UUID] = mapped_column(
        PG_UUID(as_uuid=True), ForeignKey("products.id", ondelete="RESTRICT"), nullable=False
    )
    version: Mapped[str] = mapped_column(String(100), nullable=False)
    target: Mapped[str] = mapped_column(String(200), nullable=False)
    status: Mapped[str] = mapped_column(String(20), server_default="DRAFT", nullable=False)
    storage_key: Mapped[str] = mapped_column(String(500), unique=True, nullable=False)
    filename: Mapped[str] = mapped_column(String(255), nullable=False)
    size_bytes: Mapped[int] = mapped_column(BigInteger, nullable=False)
    sha256_hex: Mapped[str] = mapped_column(String(64), nullable=False)
    manifest_bytes: Mapped[bytes] = mapped_column(LargeBinary, nullable=False)
    signature: Mapped[bytes] = mapped_column(LargeBinary, nullable=False)
    signing_key_id: Mapped[str] = mapped_column(String(100), nullable=False)
    created_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), server_default=func.now(), nullable=False
    )
    published_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True))


class ServerReleaseHead(Base):
    __tablename__ = "server_release_heads"
    __table_args__ = (
        ForeignKeyConstraint(
            ["product_id", "current_package_id"],
            ["packages.product_id", "packages.id"],
            name="fk_server_heads_current_product",
            ondelete="RESTRICT",
        ),
        ForeignKeyConstraint(
            ["product_id", "fallback_package_id"],
            ["packages.product_id", "packages.id"],
            name="fk_server_heads_fallback_product",
            ondelete="RESTRICT",
        ),
    )

    product_id: Mapped[UUID] = mapped_column(
        PG_UUID(as_uuid=True), ForeignKey("products.id", ondelete="RESTRICT"), primary_key=True
    )
    current_package_id: Mapped[UUID | None] = mapped_column(PG_UUID(as_uuid=True))
    fallback_package_id: Mapped[UUID | None] = mapped_column(PG_UUID(as_uuid=True))
    updated_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), server_default=func.now(), onupdate=func.now(), nullable=False
    )


class Device(Base):
    __tablename__ = "devices"

    id: Mapped[UUID] = mapped_column(PG_UUID(as_uuid=True), primary_key=True, default=uuid4)
    name: Mapped[str] = mapped_column(String(200), unique=True, nullable=False)
    product_id: Mapped[UUID] = mapped_column(
        PG_UUID(as_uuid=True), ForeignKey("products.id", ondelete="RESTRICT"), nullable=False
    )
    target: Mapped[str] = mapped_column(String(200), nullable=False)
    created_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), server_default=func.now(), nullable=False
    )


class DeviceTrustedPackage(Base):
    __tablename__ = "device_trusted_packages"

    device_id: Mapped[UUID] = mapped_column(
        PG_UUID(as_uuid=True), ForeignKey("devices.id", ondelete="RESTRICT"), primary_key=True
    )
    package_id: Mapped[UUID] = mapped_column(
        PG_UUID(as_uuid=True), ForeignKey("packages.id", ondelete="RESTRICT"), primary_key=True
    )
    local_storage_key: Mapped[str] = mapped_column(String(500), unique=True, nullable=False)
    verified_sha256_hex: Mapped[str] = mapped_column(String(64), nullable=False)
    verified_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), nullable=False)


class DeviceState(Base):
    __tablename__ = "device_state"
    __table_args__ = (
        ForeignKeyConstraint(
            ["device_id", "current_package_id"],
            ["device_trusted_packages.device_id", "device_trusted_packages.package_id"],
            name="fk_device_state_current_trusted",
            ondelete="RESTRICT",
        ),
        ForeignKeyConstraint(
            ["device_id", "fallback_package_id"],
            ["device_trusted_packages.device_id", "device_trusted_packages.package_id"],
            name="fk_device_state_fallback_trusted",
            ondelete="RESTRICT",
        ),
    )

    device_id: Mapped[UUID] = mapped_column(
        PG_UUID(as_uuid=True), ForeignKey("devices.id", ondelete="RESTRICT"), primary_key=True
    )
    current_package_id: Mapped[UUID | None] = mapped_column(PG_UUID(as_uuid=True))
    fallback_package_id: Mapped[UUID | None] = mapped_column(PG_UUID(as_uuid=True))
    updated_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), server_default=func.now(), nullable=False
    )


class UpdateSession(Base):
    __tablename__ = "update_sessions"
    __table_args__ = (
        CheckConstraint(
            "state IN ('IDLE', 'CHECKING', 'DOWNLOADING', 'VERIFYING', 'INSTALLING', "
            "'COMPLETED', 'NO_UPDATE', 'REJECTED', 'FAILED', 'ROLLING_BACK', 'ROLLED_BACK')",
            name="ck_update_sessions_state",
        ),
        Index("ix_update_sessions_device_created", "device_id", "created_at"),
    )

    id: Mapped[UUID] = mapped_column(PG_UUID(as_uuid=True), primary_key=True, default=uuid4)
    device_id: Mapped[UUID] = mapped_column(
        PG_UUID(as_uuid=True), ForeignKey("devices.id", ondelete="RESTRICT"), nullable=False
    )
    state: Mapped[str] = mapped_column(String(24), server_default="IDLE", nullable=False)
    original_current_package_id: Mapped[UUID | None] = mapped_column(
        PG_UUID(as_uuid=True), ForeignKey("packages.id", ondelete="RESTRICT")
    )
    original_fallback_package_id: Mapped[UUID | None] = mapped_column(
        PG_UUID(as_uuid=True), ForeignKey("packages.id", ondelete="RESTRICT")
    )
    target_package_id: Mapped[UUID | None] = mapped_column(
        PG_UUID(as_uuid=True), ForeignKey("packages.id", ondelete="RESTRICT")
    )
    verification_result: Mapped[str | None] = mapped_column(String(100))
    failure_code: Mapped[str | None] = mapped_column(String(100))
    scenario_type: Mapped[str | None] = mapped_column(String(100))
    scenario_config: Mapped[dict[str, Any] | None] = mapped_column(JSONB)
    created_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), server_default=func.now(), nullable=False
    )
    started_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True))
    finished_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True))


class TemporaryStorage(Base):
    __tablename__ = "temporary_storage"
    __table_args__ = (
        CheckConstraint("state IN ('WRITE', 'SEALED', 'VERIFIED', 'REJECTED')", name="ck_temporary_storage_state"),
        CheckConstraint("bytes_written >= 0", name="ck_temporary_storage_bytes_nonnegative"),
    )

    session_id: Mapped[UUID] = mapped_column(
        PG_UUID(as_uuid=True), ForeignKey("update_sessions.id", ondelete="RESTRICT"), primary_key=True
    )
    state: Mapped[str] = mapped_column(String(20), server_default="WRITE", nullable=False)
    storage_key: Mapped[str] = mapped_column(String(500), unique=True, nullable=False)
    bytes_written: Mapped[int] = mapped_column(BigInteger, server_default="0", nullable=False)
    sealed_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True))
    verified_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True))
    cleaned_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True))


class AuditEvent(Base):
    __tablename__ = "audit_events"
    __table_args__ = (
        Index("ix_audit_events_session_created", "session_id", "created_at", "id"),
    )

    id: Mapped[int] = mapped_column(BigInteger, primary_key=True, autoincrement=True)
    session_id: Mapped[UUID | None] = mapped_column(
        PG_UUID(as_uuid=True), ForeignKey("update_sessions.id", ondelete="RESTRICT")
    )
    created_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), server_default=func.now(), nullable=False
    )
    event_type: Mapped[str] = mapped_column(String(100), nullable=False)
    component: Mapped[str] = mapped_column(String(100), nullable=False)
    level: Mapped[str] = mapped_column(String(20), nullable=False)
    message: Mapped[str] = mapped_column(Text, nullable=False)
    details: Mapped[dict[str, Any]] = mapped_column(
        JSONB, server_default=text("'{}'::jsonb"), nullable=False
    )
