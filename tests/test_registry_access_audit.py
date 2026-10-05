"""Registry and HTTP denials survive rollback and are recorded exactly once."""

import asyncio
from uuid import uuid4

import pytest
from httpx import ASGITransport, AsyncClient
from sqlalchemy import delete, or_, select

from app.db.models import AuditEvent, Package, Product, ServerReleaseHead
from app.db.session import SessionFactory, engine
from app.domain import rules
from app.domain.rules import AccessDeniedError, RegistryAction, RegistryRole
from app.main import app
from app.services.packages import PackageRegistryService, RegistryNotFound, UpdateServerService


def test_registry_and_api_access_denials(monkeypatch):
    async def exercise():
        await engine.dispose()
        resource_id = uuid4()
        resource = str(resource_id)
        sentinel_id = uuid4()
        scope = or_(*[
            AuditEvent.details[key].astext == resource
            for key in ("product_id", "package_id", "device_id", "product_name")
        ])
        count = 0

        async def check_event(component, actor, operation):
            nonlocal count
            count += 1
            async with SessionFactory() as observer:
                events = list(await observer.scalars(
                    select(AuditEvent).where(scope).order_by(AuditEvent.id)
                ))
                assert len(events) == count
                event = events[-1]
                assert event.event_type == "ACCESS_DENIED"
                assert event.component == component and event.level == "WARNING"
                assert event.details["actor"] == actor
                assert event.details["operation"] == operation
                assert await observer.get(Product, sentinel_id) is None

        try:
            async with SessionFactory() as session:
                registry = PackageRegistryService(session)
                session.add(Product(id=sentinel_id, name=f"pending-{sentinel_id.hex}", target="test"))
                await session.flush()
                with pytest.raises(AccessDeniedError):
                    await registry.create_product(resource, "test", RegistryRole.DEVICE)
                await session.rollback()
                await check_event("PackageRegistryService", "device", "create_product")
                with pytest.raises(AccessDeniedError):
                    await registry.publish_package(resource_id, "1.0", "test.pkg", b"data", RegistryRole.DEVICE)
                await session.rollback()
                await check_event("PackageRegistryService", "device", "publish_package")

                # Both current roles may read releases. Restrict this policy in the
                # test to exercise every read gate without introducing a new role.
                monkeypatch.setitem(rules._ALLOWED, RegistryAction.READ_RELEASE, {RegistryRole.PUBLISHER})
                server = UpdateServerService(session)
                for method in (server.list_packages, server.latest, server.manifest, server.download):
                    with pytest.raises(AccessDeniedError):
                        await method(resource_id, RegistryRole.DEVICE)
                    await session.rollback()
                    await check_event("UpdateServerService", "device", "read_release")

            async with AsyncClient(transport=ASGITransport(app=app), base_url="http://test") as client:
                denied = await client.post(
                    f"/products/{resource_id}/packages", data={"version": "1.0"},
                    files={"file": ("test.pkg", b"data")},
                )
                assert denied.status_code == 403
                await check_event("PackageRegistryService", "device", "publish_package")
                for path in (f"/products/{resource_id}/latest", f"/devices/{resource_id}/updates/download"):
                    if path.endswith("download"):
                        denied = await client.post(path, headers={"Role": "unknown"})
                    else:
                        denied = await client.get(path, headers={"Role": "unknown"})
                    assert denied.status_code == 403
                    await check_event("RegistryAPI", "unknown", "resolve_role")
                denied = await client.post(f"/devices/{resource_id}/updates/download")
                assert denied.status_code == 403
                await check_event("UpdatesAPI", "device", "read_release")
        finally:
            async with SessionFactory() as cleanup:
                await cleanup.execute(delete(AuditEvent).where(scope))
                await cleanup.execute(delete(Product).where(Product.id == sentinel_id))
                await cleanup.commit()
            await engine.dispose()

    asyncio.run(exercise())


def test_unpublished_package_denial_is_audited():
    async def exercise():
        await engine.dispose()
        product_id = uuid4()
        package_id = uuid4()
        try:
            async with SessionFactory() as session:
                session.add(Product(id=product_id, name=f"draft-{product_id.hex}", target="test"))
                await session.flush()
                session.add(Package(
                    id=package_id, product_id=product_id, version="1.0", target="test",
                    status="DRAFT", storage_key=f"server/{package_id.hex}.pkg", filename="draft.pkg",
                    size_bytes=1, sha256_hex="0" * 64, manifest_bytes=b"{}", signature=b"",
                    signing_key_id="test",
                ))
                await session.flush()
                session.add(ServerReleaseHead(product_id=product_id, current_package_id=package_id))
                await session.commit()
                server = UpdateServerService(session)
                for count, (method, resource_id) in enumerate([
                    (server.latest, product_id), (server.manifest, package_id), (server.download, package_id),
                ], start=1):
                    with pytest.raises(RegistryNotFound):
                        await method(resource_id, RegistryRole.DEVICE)
                    await session.rollback()
                    async with SessionFactory() as observer:
                        events = list(await observer.scalars(select(AuditEvent).where(
                            AuditEvent.details["package_id"].astext == str(package_id),
                        )))
                        assert len(events) == count
                        assert all(e.event_type == "ACCESS_DENIED" for e in events)
                        assert all(e.details["reason"] == "not_published" for e in events)
        finally:
            async with SessionFactory() as cleanup:
                await cleanup.execute(delete(AuditEvent).where(
                    AuditEvent.details["package_id"].astext == str(package_id),
                ))
                await cleanup.execute(delete(ServerReleaseHead).where(ServerReleaseHead.product_id == product_id))
                await cleanup.execute(delete(Package).where(Package.id == package_id))
                await cleanup.execute(delete(Product).where(Product.id == product_id))
                await cleanup.commit()
            await engine.dispose()

    asyncio.run(exercise())
