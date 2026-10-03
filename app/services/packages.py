"""Publish signed packages and serve only published releases."""

import json
from datetime import datetime, timezone
from pathlib import Path
from uuid import UUID, uuid4

from packaging.version import InvalidVersion, Version
from sqlalchemy import select
from sqlalchemy.exc import IntegrityError
from sqlalchemy.ext.asyncio import AsyncSession

from app.db.models import Package, Product, ServerReleaseHead
from app.domain.rules import RegistryAction, RegistryRole, require_access
from app.infrastructure.crypto import TrainingSigner, sha256_hex
from app.infrastructure.files import ServerFileStore
from app.services.monitor import MonitorService


class RegistryNotFound(Exception):
    pass


class NoPublishedRelease(RegistryNotFound):
    pass


class RegistryConflict(Exception):
    pass


class InvalidPackage(Exception):
    pass


class PackageRegistryService:
    def __init__(
        self,
        session: AsyncSession,
        files: ServerFileStore | None = None,
        signer: TrainingSigner | None = None,
    ) -> None:
        self.session = session
        self.files = files or ServerFileStore()
        self.signer = signer or TrainingSigner()
        self.monitor = MonitorService(session)

    async def create_product(self, name: str, target: str, role: RegistryRole) -> Product:
        require_access(role, RegistryAction.CREATE_PRODUCT)
        product = Product(id=uuid4(), name=name.strip(), target=target.strip())
        if not product.name or not product.target:
            raise InvalidPackage("Product name and target are required")
        self.session.add(product)
        self.monitor.record(
            "PRODUCT_CREATED",
            "Product created",
            component="PackageRegistryService",
            details={"product_id": str(product.id), "name": product.name},
        )
        try:
            await self.session.commit()
        except IntegrityError as exc:
            await self.session.rollback()
            raise RegistryConflict("Product name already exists") from exc
        await self.session.refresh(product)
        return product

    async def publish_package(
        self,
        product_id: UUID,
        version: str,
        filename: str,
        content: bytes,
        role: RegistryRole,
    ) -> Package:
        require_access(role, RegistryAction.PUBLISH_PACKAGE)
        version = version.strip()
        try:
            candidate_version = Version(version)
        except InvalidVersion as exc:
            raise InvalidPackage("Version must be a valid PEP 440 version") from exc
        if not filename or filename != Path(filename).name or filename in {".", ".."}:
            raise InvalidPackage("Filename must not contain a path")
        if not content:
            raise InvalidPackage("Package file must not be empty")

        storage_key: str | None = None
        try:
            product = await self.session.get(Product, product_id, with_for_update=True)
            if product is None:
                raise RegistryNotFound("Product not found")
            head = await self.session.get(ServerReleaseHead, product_id)
            if head and head.current_package_id:
                current = await self.session.get(Package, head.current_package_id)
                if current is not None and candidate_version <= Version(current.version):
                    raise RegistryConflict("New package version must be newer than current")

            package_id = uuid4()
            key_id = self.signer.key_id()
            manifest = {
                "package_id": str(package_id),
                "product_id": str(product_id),
                "version": version,
                "target": product.target,
                "filename": filename,
                "size_bytes": len(content),
                "sha256_hex": sha256_hex(content),
                "signature_algorithm": "ed25519",
                "signing_key_id": key_id,
            }
            manifest_bytes = json.dumps(
                manifest, sort_keys=True, separators=(",", ":"), ensure_ascii=False
            ).encode("utf-8")
            signature = self.signer.sign(manifest_bytes)
            storage_key = self.files.save(package_id, content)

            package = Package(
                id=package_id,
                product_id=product_id,
                version=version,
                target=product.target,
                status="PUBLISHED",
                storage_key=storage_key,
                filename=filename,
                size_bytes=len(content),
                sha256_hex=manifest["sha256_hex"],
                manifest_bytes=manifest_bytes,
                signature=signature,
                signing_key_id=key_id,
                published_at=datetime.now(timezone.utc),
            )
            self.session.add(package)
            if head is None:
                head = ServerReleaseHead(product_id=product_id)
                self.session.add(head)
            head.fallback_package_id = head.current_package_id
            head.current_package_id = package_id
            head.updated_at = datetime.now(timezone.utc)
            self.monitor.record(
                "PACKAGE_PUBLISHED",
                f"Published version {version}",
                component="PackageRegistryService",
                details={
                    "product_id": str(product_id),
                    "package_id": str(package_id),
                    "version": version,
                    "sha256_hex": manifest["sha256_hex"],
                },
            )
            await self.session.commit()
        except Exception as exc:
            await self.session.rollback()
            if storage_key is not None:
                self.files.delete(storage_key)
            if isinstance(exc, IntegrityError):
                raise RegistryConflict("This product version already exists") from exc
            raise
        await self.session.refresh(package)
        return package


class UpdateServerService:
    def __init__(self, session: AsyncSession, files: ServerFileStore | None = None) -> None:
        self.session = session
        self.files = files or ServerFileStore()

    async def list_packages(self, product_id: UUID, role: RegistryRole) -> list[Package]:
        require_access(role, RegistryAction.READ_RELEASE)
        if await self.session.get(Product, product_id) is None:
            raise RegistryNotFound("Product not found")
        result = await self.session.execute(
            select(Package)
            .where(Package.product_id == product_id, Package.status == "PUBLISHED")
            .order_by(Package.published_at.desc(), Package.created_at.desc())
        )
        return list(result.scalars())

    async def latest(self, product_id: UUID, role: RegistryRole) -> Package:
        require_access(role, RegistryAction.READ_RELEASE)
        if await self.session.get(Product, product_id) is None:
            raise RegistryNotFound("Product not found")
        head = await self.session.get(ServerReleaseHead, product_id)
        if head is None or head.current_package_id is None:
            raise NoPublishedRelease("No published package for this product")
        return await self._published_package(head.current_package_id)

    async def manifest(self, package_id: UUID, role: RegistryRole) -> Package:
        require_access(role, RegistryAction.READ_RELEASE)
        return await self._published_package(package_id)

    async def download(self, package_id: UUID, role: RegistryRole) -> tuple[Package, bytes]:
        require_access(role, RegistryAction.READ_RELEASE)
        package = await self._published_package(package_id)
        try:
            content = self.files.read(package.storage_key)
        except FileNotFoundError as exc:
            raise RegistryNotFound("Package content is missing") from exc
        return package, content

    async def _published_package(self, package_id: UUID) -> Package:
        package = await self.session.get(Package, package_id)
        if package is None or package.status != "PUBLISHED":
            raise RegistryNotFound("Published package not found")
        return package
