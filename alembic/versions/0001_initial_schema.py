"""Create the initial registry and update tables.

Revision ID: 0001_initial_schema
Revises:
"""

from collections.abc import Sequence

from alembic import op
import sqlalchemy as sa
from sqlalchemy.dialects import postgresql

revision: str = "0001_initial_schema"
down_revision: str | None = None
branch_labels: str | Sequence[str] | None = None
depends_on: str | Sequence[str] | None = None

UUID = postgresql.UUID(as_uuid=True)


def upgrade() -> None:
    op.create_table(
        "products",
        sa.Column("id", UUID, primary_key=True),
        sa.Column("name", sa.String(200), nullable=False, unique=True),
        sa.Column("target", sa.String(200), nullable=False),
        sa.Column("created_at", sa.DateTime(timezone=True), server_default=sa.func.now(), nullable=False),
    )
    op.create_table(
        "packages",
        sa.Column("id", UUID, primary_key=True),
        sa.Column("product_id", UUID, sa.ForeignKey("products.id", ondelete="RESTRICT"), nullable=False),
        sa.Column("version", sa.String(100), nullable=False),
        sa.Column("target", sa.String(200), nullable=False),
        sa.Column("status", sa.String(20), server_default="DRAFT", nullable=False),
        sa.Column("storage_key", sa.String(500), nullable=False, unique=True),
        sa.Column("filename", sa.String(255), nullable=False),
        sa.Column("size_bytes", sa.BigInteger(), nullable=False),
        sa.Column("sha256_hex", sa.String(64), nullable=False),
        sa.Column("manifest_bytes", sa.LargeBinary(), nullable=False),
        sa.Column("signature", sa.LargeBinary(), nullable=False),
        sa.Column("signing_key_id", sa.String(100), nullable=False),
        sa.Column("created_at", sa.DateTime(timezone=True), server_default=sa.func.now(), nullable=False),
        sa.Column("published_at", sa.DateTime(timezone=True)),
        sa.CheckConstraint("size_bytes >= 0", name="ck_packages_size_nonnegative"),
        sa.CheckConstraint("status IN ('DRAFT', 'PUBLISHED')", name="ck_packages_status"),
        sa.UniqueConstraint("product_id", "version", "target", name="uq_packages_release"),
        sa.UniqueConstraint("product_id", "id", name="uq_packages_product_id"),
    )
    op.create_index("ix_packages_product_status", "packages", ["product_id", "status"])
    op.create_table(
        "server_release_heads",
        sa.Column("product_id", UUID, sa.ForeignKey("products.id", ondelete="RESTRICT"), primary_key=True),
        sa.Column("current_package_id", UUID),
        sa.Column("fallback_package_id", UUID),
        sa.Column("updated_at", sa.DateTime(timezone=True), server_default=sa.func.now(), nullable=False),
        sa.ForeignKeyConstraint(
            ["product_id", "current_package_id"], ["packages.product_id", "packages.id"],
            name="fk_server_heads_current_product", ondelete="RESTRICT",
        ),
        sa.ForeignKeyConstraint(
            ["product_id", "fallback_package_id"], ["packages.product_id", "packages.id"],
            name="fk_server_heads_fallback_product", ondelete="RESTRICT",
        ),
    )
    op.create_table(
        "devices",
        sa.Column("id", UUID, primary_key=True),
        sa.Column("name", sa.String(200), nullable=False, unique=True),
        sa.Column("product_id", UUID, sa.ForeignKey("products.id", ondelete="RESTRICT"), nullable=False),
        sa.Column("target", sa.String(200), nullable=False),
        sa.Column("created_at", sa.DateTime(timezone=True), server_default=sa.func.now(), nullable=False),
    )
    op.create_table(
        "device_trusted_packages",
        sa.Column("device_id", UUID, sa.ForeignKey("devices.id", ondelete="RESTRICT"), primary_key=True),
        sa.Column("package_id", UUID, sa.ForeignKey("packages.id", ondelete="RESTRICT"), primary_key=True),
        sa.Column("local_storage_key", sa.String(500), nullable=False, unique=True),
        sa.Column("verified_sha256_hex", sa.String(64), nullable=False),
        sa.Column("verified_at", sa.DateTime(timezone=True), nullable=False),
    )
    op.create_table(
        "device_state",
        sa.Column("device_id", UUID, sa.ForeignKey("devices.id", ondelete="RESTRICT"), primary_key=True),
        sa.Column("current_package_id", UUID),
        sa.Column("fallback_package_id", UUID),
        sa.Column("updated_at", sa.DateTime(timezone=True), server_default=sa.func.now(), nullable=False),
        sa.ForeignKeyConstraint(
            ["device_id", "current_package_id"],
            ["device_trusted_packages.device_id", "device_trusted_packages.package_id"],
            name="fk_device_state_current_trusted", ondelete="RESTRICT",
        ),
        sa.ForeignKeyConstraint(
            ["device_id", "fallback_package_id"],
            ["device_trusted_packages.device_id", "device_trusted_packages.package_id"],
            name="fk_device_state_fallback_trusted", ondelete="RESTRICT",
        ),
    )
    op.create_table(
        "update_sessions",
        sa.Column("id", UUID, primary_key=True),
        sa.Column("device_id", UUID, sa.ForeignKey("devices.id", ondelete="RESTRICT"), nullable=False),
        sa.Column("state", sa.String(24), server_default="IDLE", nullable=False),
        sa.Column("original_current_package_id", UUID, sa.ForeignKey("packages.id", ondelete="RESTRICT")),
        sa.Column("original_fallback_package_id", UUID, sa.ForeignKey("packages.id", ondelete="RESTRICT")),
        sa.Column("target_package_id", UUID, sa.ForeignKey("packages.id", ondelete="RESTRICT")),
        sa.Column("verification_result", sa.String(100)),
        sa.Column("failure_code", sa.String(100)),
        sa.Column("scenario_type", sa.String(100)),
        sa.Column("scenario_config", postgresql.JSONB()),
        sa.Column("created_at", sa.DateTime(timezone=True), server_default=sa.func.now(), nullable=False),
        sa.Column("started_at", sa.DateTime(timezone=True)),
        sa.Column("finished_at", sa.DateTime(timezone=True)),
        sa.CheckConstraint(
            "state IN ('IDLE', 'CHECKING', 'DOWNLOADING', 'VERIFYING', 'INSTALLING', "
            "'COMPLETED', 'NO_UPDATE', 'REJECTED', 'FAILED', 'ROLLING_BACK', 'ROLLED_BACK')",
            name="ck_update_sessions_state",
        ),
    )
    op.create_index("ix_update_sessions_device_created", "update_sessions", ["device_id", "created_at"])
    op.create_table(
        "temporary_storage",
        sa.Column("session_id", UUID, sa.ForeignKey("update_sessions.id", ondelete="RESTRICT"), primary_key=True),
        sa.Column("state", sa.String(20), server_default="WRITE", nullable=False),
        sa.Column("storage_key", sa.String(500), nullable=False, unique=True),
        sa.Column("bytes_written", sa.BigInteger(), server_default="0", nullable=False),
        sa.Column("sealed_at", sa.DateTime(timezone=True)),
        sa.Column("verified_at", sa.DateTime(timezone=True)),
        sa.Column("cleaned_at", sa.DateTime(timezone=True)),
        sa.CheckConstraint("state IN ('WRITE', 'SEALED', 'VERIFIED', 'REJECTED')", name="ck_temporary_storage_state"),
        sa.CheckConstraint("bytes_written >= 0", name="ck_temporary_storage_bytes_nonnegative"),
    )
    op.create_table(
        "audit_events",
        sa.Column("id", sa.BigInteger(), primary_key=True, autoincrement=True),
        sa.Column("session_id", UUID, sa.ForeignKey("update_sessions.id", ondelete="RESTRICT")),
        sa.Column("created_at", sa.DateTime(timezone=True), server_default=sa.func.now(), nullable=False),
        sa.Column("event_type", sa.String(100), nullable=False),
        sa.Column("component", sa.String(100), nullable=False),
        sa.Column("level", sa.String(20), nullable=False),
        sa.Column("message", sa.Text(), nullable=False),
        sa.Column("details", postgresql.JSONB(), server_default=sa.text("'{}'::jsonb"), nullable=False),
    )
    op.create_index("ix_audit_events_session_created", "audit_events", ["session_id", "created_at", "id"])


def downgrade() -> None:
    op.drop_index("ix_audit_events_session_created", table_name="audit_events")
    op.drop_table("audit_events")
    op.drop_table("temporary_storage")
    op.drop_index("ix_update_sessions_device_created", table_name="update_sessions")
    op.drop_table("update_sessions")
    op.drop_table("device_state")
    op.drop_table("device_trusted_packages")
    op.drop_table("devices")
    op.drop_table("server_release_heads")
    op.drop_index("ix_packages_product_status", table_name="packages")
    op.drop_table("packages")
    op.drop_table("products")
