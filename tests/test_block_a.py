"""Integration checks for publication against the configured local PostgreSQL."""

import asyncio
import json
from uuid import UUID, uuid4

import pytest
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PublicKey
from httpx import ASGITransport, AsyncClient
from sqlalchemy import delete, select, text

from app.main import app
from app.db.models import Package, Product, ServerReleaseHead
from app.db.session import SessionFactory, engine
from app.domain.rules import AccessDeniedError, RegistryRole
from app.infrastructure.crypto import TrainingSigner, sha256_hex
from app.infrastructure.files import ServerFileStore
from app.services.gateway import (
    ExternalNetworkGateway,
    NetworkUnavailableError,
    UntrustedServerError,
)
from app.services.packages import PackageRegistryService, RegistryConflict, UpdateServerService


def test_publish_latest_download_audit_and_access(tmp_path):
    async def exercise() -> None:
        await engine.dispose()
        files = ServerFileStore(tmp_path)
        signer = TrainingSigner(tmp_path / "signing_key.raw")
        product_id = None
        storage_keys: list[str] = []
        try:
            async with SessionFactory() as session:
                registry = PackageRegistryService(session, files, signer)
                server = UpdateServerService(session, files)
                with pytest.raises(AccessDeniedError):
                    await registry.create_product("forbidden", "linux-x64", RegistryRole.DEVICE)

                product = await registry.create_product(
                    f"block-a-{uuid4().hex}", "linux-x64", RegistryRole.PUBLISHER
                )
                product_id = product.id
                first = await registry.publish_package(
                    product_id, "1.0.0", "demo.pkg", b"first", RegistryRole.PUBLISHER
                )
                storage_keys.append(first.storage_key)
                second = await registry.publish_package(
                    product_id, "1.1.0", "demo.pkg", b"second", RegistryRole.PUBLISHER
                )
                storage_keys.append(second.storage_key)

                head = await session.get(ServerReleaseHead, product_id)
                assert head.current_package_id == second.id
                assert head.fallback_package_id == first.id
                assert [p.id for p in await server.list_packages(product_id, RegistryRole.DEVICE)] == [
                    second.id, first.id
                ]

                gateway = ExternalNetworkGateway(server)
                assert (await gateway.latest(product_id)).id == second.id
                manifest_package = await gateway.manifest(second.id)
                assert json.loads(manifest_package.manifest_bytes)["sha256_hex"] == sha256_hex(b"second")
                Ed25519PublicKey.from_public_bytes(signer.public_key_bytes()).verify(
                    manifest_package.signature, manifest_package.manifest_bytes
                )
                _, downloaded = await gateway.download(second.id)
                assert downloaded == b"second"

                with pytest.raises(RegistryConflict):
                    await registry.publish_package(
                        product_id, "1.0.0", "demo.pkg", b"old", RegistryRole.PUBLISHER
                    )
                with pytest.raises(UntrustedServerError):
                    await ExternalNetworkGateway(server, server_trusted=False).latest(product_id)
                with pytest.raises(NetworkUnavailableError):
                    await ExternalNetworkGateway(server, network_available=False).latest(product_id)

                events = await session.execute(
                    text("SELECT event_type FROM audit_events WHERE details ->> 'product_id' = :product_id"),
                    {"product_id": str(product_id)},
                )
                assert sorted(events.scalars()) == [
                    "PACKAGE_PUBLISHED", "PACKAGE_PUBLISHED", "PRODUCT_CREATED"
                ]
        finally:
            if product_id is not None:
                async with SessionFactory() as cleanup:
                    await cleanup.execute(
                        text("DELETE FROM audit_events WHERE details ->> 'product_id' = :product_id"),
                        {"product_id": str(product_id)},
                    )
                    await cleanup.execute(
                        delete(ServerReleaseHead).where(ServerReleaseHead.product_id == product_id)
                    )
                    await cleanup.execute(delete(Package).where(Package.product_id == product_id))
                    await cleanup.execute(delete(Product).where(Product.id == product_id))
                    await cleanup.commit()
            for key in storage_keys:
                files.delete(key)
            await engine.dispose()

    asyncio.run(exercise())


def test_http_publication_and_download():
    async def exercise() -> None:
        await engine.dispose()
        product_id = None
        storage_keys: list[str] = []
        try:
            async with AsyncClient(transport=ASGITransport(app=app), base_url="http://test") as client:
                name = f"block-a-api-{uuid4().hex}"
                denied = await client.post("/products", json={"name": name, "target": "linux-x64"})
                assert denied.status_code == 403

                created = await client.post(
                    "/products",
                    json={"name": name, "target": "linux-x64"},
                    headers={"X-Registry-Role": "publisher"},
                )
                assert created.status_code == 201, created.text
                product_id = UUID(created.json()["id"])

                published = await client.post(
                    f"/products/{product_id}/packages",
                    data={"version": "1.0.0"},
                    files={"file": ("demo.pkg", b"api-package", "application/octet-stream")},
                    headers={"X-Registry-Role": "publisher"},
                )
                assert published.status_code == 201, published.text
                package_id = published.json()["id"]

                latest = await client.get(f"/products/{product_id}/latest")
                assert latest.status_code == 200
                assert latest.json()["id"] == package_id
                history = await client.get(f"/products/{product_id}/packages")
                assert [p["id"] for p in history.json()] == [package_id]
                manifest = await client.get(f"/packages/{package_id}/manifest")
                assert manifest.status_code == 200
                assert manifest.json()["manifest"]["sha256_hex"] == sha256_hex(b"api-package")
                content = await client.get(f"/packages/{package_id}/content")
                assert content.status_code == 200
                assert content.content == b"api-package"
        finally:
            if product_id is not None:
                async with SessionFactory() as cleanup:
                    storage_keys = list(
                        (await cleanup.execute(
                            select(Package.storage_key).where(Package.product_id == product_id)
                        )).scalars()
                    )
                    await cleanup.execute(
                        text("DELETE FROM audit_events WHERE details ->> 'product_id' = :product_id"),
                        {"product_id": str(product_id)},
                    )
                    await cleanup.execute(
                        delete(ServerReleaseHead).where(ServerReleaseHead.product_id == product_id)
                    )
                    await cleanup.execute(delete(Package).where(Package.product_id == product_id))
                    await cleanup.execute(delete(Product).where(Product.id == product_id))
                    await cleanup.commit()
            for key in storage_keys:
                ServerFileStore().delete(key)
            await engine.dispose()

    asyncio.run(exercise())
