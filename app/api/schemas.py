"""Public API request and response schemas."""

from datetime import datetime
from typing import Any
from uuid import UUID

from pydantic import BaseModel, ConfigDict, Field
from app.domain.enums import ScenarioType


class ProductCreate(BaseModel):
    name: str = Field(min_length=1, max_length=200)
    target: str = Field(min_length=1, max_length=200)


class ProductRead(BaseModel):
    model_config = ConfigDict(from_attributes=True)

    id: UUID
    name: str
    target: str
    created_at: datetime


class PackageRead(BaseModel):
    model_config = ConfigDict(from_attributes=True)

    id: UUID
    product_id: UUID
    version: str
    target: str
    status: str
    filename: str
    size_bytes: int
    sha256_hex: str
    published_at: datetime | None


class ManifestRead(BaseModel):
    manifest: dict[str, Any]
    signature_base64: str
    signing_key_id: str


class AuditEventRead(BaseModel):
    model_config = ConfigDict(from_attributes=True)

    id: int
    session_id: UUID | None
    created_at: datetime
    event_type: str
    component: str
    level: str
    message: str
    details: dict[str, Any]


class DeviceCreate(BaseModel):
    name: str = Field(min_length=1, max_length=200)
    product_id: UUID
    target: str = Field(min_length=1, max_length=200)


class DeviceRead(BaseModel):
    id: UUID
    name: str
    product_id: UUID
    target: str
    current_package_id: UUID | None
    fallback_package_id: UUID | None


class TemporaryStorageRead(BaseModel):
    model_config = ConfigDict(from_attributes=True)

    state: str
    bytes_written: int
    sealed_at: datetime | None
    verified_at: datetime | None
    cleaned_at: datetime | None


class UpdateSessionRead(BaseModel):
    model_config = ConfigDict(from_attributes=True)

    id: UUID
    device_id: UUID
    state: str
    original_current_package_id: UUID | None
    original_fallback_package_id: UUID | None
    target_package_id: UUID | None
    verification_result: str | None
    failure_code: str | None
    scenario_type: ScenarioType | None = None
    scenario_config: dict[str, Any] | None = None
    created_at: datetime
    started_at: datetime | None
    finished_at: datetime | None
    temporary_storage: TemporaryStorageRead | None = None
