"""Downloader/storage integration checks; all created database records are removed."""

import asyncio
from uuid import UUID, uuid4

import pytest
from httpx import ASGITransport, AsyncClient
from sqlalchemy import delete, select, text

from app.db.models import (
    AuditEvent, Device, DeviceState, Package, Product, ServerReleaseHead,
    TemporaryStorage, UpdateSession,
)
from app.db.session import SessionFactory, engine
from app.domain.rules import AccessDeniedError, StorageActor, RegistryRole
from app.infrastructure.crypto import TrainingSigner
from app.infrastructure.files import ServerFileStore, TemporaryFileStore
from app.main import app
from app.services.downloader import DownloadConflict, DownloaderService
from app.services.gateway import ExternalNetworkGateway
from app.services.monitor import MonitorService
from app.services.packages import PackageRegistryService, UpdateServerService
from app.services.temporary_storage import TemporaryStorageError, TemporaryStorageService


async def remove_test_product(product_id):
    async with SessionFactory() as session:
        device_ids = select(Device.id).where(Device.product_id == product_id)
        session_ids = select(UpdateSession.id).where(UpdateSession.device_id.in_(device_ids))
        await session.execute(delete(AuditEvent).where(AuditEvent.session_id.in_(session_ids)))
        await session.execute(delete(TemporaryStorage).where(TemporaryStorage.session_id.in_(session_ids)))
        await session.execute(delete(UpdateSession).where(UpdateSession.device_id.in_(device_ids)))
        await session.execute(delete(DeviceState).where(DeviceState.device_id.in_(device_ids)))
        await session.execute(delete(Device).where(Device.product_id == product_id))
        keys = list((await session.scalars(select(Package.storage_key).where(Package.product_id == product_id))))
        await session.execute(delete(ServerReleaseHead).where(ServerReleaseHead.product_id == product_id))
        await session.execute(delete(Package).where(Package.product_id == product_id))
        await session.execute(text("DELETE FROM audit_events WHERE details ->> 'product_id' = :id"), {"id": str(product_id)})
        await session.execute(delete(Product).where(Product.id == product_id))
        await session.commit()
        return keys


@pytest.mark.parametrize("mode", ["success", "untrusted", "network", "partial_failure", "no_release"])
def test_downloader_states_and_failures(tmp_path, mode):
    async def exercise():
        await engine.dispose()
        product_id = None
        server_files = ServerFileStore(tmp_path)

        class FailingFiles(TemporaryFileStore):
            writes = 0

            def append(self, key, content, expected_size):
                self.writes += 1
                if self.writes == 2:
                    raise OSError("Simulated disk failure")
                super().append(key, content, expected_size)

        temp_files = FailingFiles(tmp_path) if mode == "partial_failure" else TemporaryFileStore(tmp_path)
        try:
            async with SessionFactory() as session:
                registry = PackageRegistryService(session, server_files, TrainingSigner(tmp_path / "test.key"))
                product = await registry.create_product(f"block-b-{uuid4().hex}", "linux-x64", RegistryRole.PUBLISHER)
                product_id = product.id
                payload = b"x" * (DownloaderService.CHUNK_BYTES + 7)
                package = None
                if mode != "no_release":
                    package = await registry.publish_package(product_id, "1.0", "test.pkg", payload, RegistryRole.PUBLISHER)
                device_id = uuid4()
                session.add(Device(id=device_id, name=f"device-{device_id.hex}", product_id=product_id, target=product.target))
                await session.flush()
                session.add(DeviceState(device_id=device_id))
                await session.commit()
                gateway = ExternalNetworkGateway(
                    UpdateServerService(session, server_files),
                    server_trusted=mode != "untrusted", network_available=mode != "network",
                )
                storage = TemporaryStorageService(session, temp_files)
                downloader = DownloaderService(session, gateway, storage)
                update = await downloader.download(device_id)
                update_id = update.id
                row = await session.get(TemporaryStorage, update_id)
                events = [e.event_type for e in await MonitorService(session).events_for_session(update_id)]
                if mode == "success":
                    assert update.state == "VERIFYING"
                    assert row.state == "SEALED" and row.bytes_written == len(payload)
                    assert row.verified_at is None and update.verification_result is None
                    assert events == ["UPDATE_CHECK_STARTED", "UPDATE_FOUND", "DOWNLOAD_STARTED",
                                      "STORAGE_CREATED", "DOWNLOAD_COMPLETED", "STORAGE_SEALED"]
                    bundle = await storage.read(update_id, StorageActor.VERIFIER)
                    assert bundle.content == payload and bundle.manifest_bytes == package.manifest_bytes
                    assert bundle.signature == package.signature
                    for actor in (StorageActor.DOWNLOADER, StorageActor.INSTALLER):
                        with pytest.raises(AccessDeniedError):
                            await storage.read(update_id, actor)
                    with pytest.raises(AccessDeniedError):
                        await storage.append(update_id, b"evil", StorageActor.DOWNLOADER)
                    with pytest.raises(AccessDeniedError):
                        await storage.set_verification_result(update_id, True, StorageActor.DOWNLOADER)
                    with pytest.raises(DownloadConflict):
                        await downloader.download(device_id)
                    await storage.set_verification_result(update_id, True, StorageActor.VERIFIER)
                    await session.commit()
                    assert (await storage.read(update_id, StorageActor.INSTALLER)).content == payload
                    await storage.cleanup(update_id, StorageActor.MANAGER)
                    await session.commit()
                    with pytest.raises(TemporaryStorageError):
                        await storage.read(update_id, StorageActor.INSTALLER)
                elif mode == "no_release":
                    assert update.state == "NO_UPDATE" and update.finished_at is not None
                    assert row is None and events == ["UPDATE_CHECK_STARTED", "NO_UPDATE"]
                else:
                    assert update.state == "FAILED" and update.finished_at is not None
                    assert "DOWNLOAD_FAILED" in events and "STORAGE_SEALED" not in events
                    if mode == "partial_failure":
                        assert row.state == "WRITE" and row.cleaned_at is not None
                        assert row.bytes_written == DownloaderService.CHUNK_BYTES
                        assert not temp_files._path(row.storage_key).exists()
                    else:
                        assert row is None
                await session.rollback()
        finally:
            if product_id is not None:
                await remove_test_product(product_id)
            await engine.dispose()

    asyncio.run(exercise())


def test_write_sealed_rejected_access(tmp_path):
    async def exercise():
        await engine.dispose()
        product_id = None
        try:
            async with SessionFactory() as session:
                product = Product(id=uuid4(), name=f"storage-{uuid4().hex}", target="test")
                product_id = product.id
                session.add(product)
                await session.flush()
                device = Device(id=uuid4(), name=f"storage-device-{uuid4().hex}", product_id=product_id, target="test")
                session.add(device)
                await session.flush()
                update = UpdateSession(id=uuid4(), device_id=device.id, state="DOWNLOADING")
                session.add(update)
                await session.commit()
                storage = TemporaryStorageService(session, TemporaryFileStore(tmp_path))
                await storage.create(update.id, b"manifest", b"signature", "test-key", StorageActor.DOWNLOADER)
                await storage.append(update.id, b"data", StorageActor.DOWNLOADER)
                await session.commit()
                for actor in (StorageActor.DOWNLOADER, StorageActor.VERIFIER, StorageActor.INSTALLER):
                    with pytest.raises(AccessDeniedError):
                        await storage.read(update.id, actor)
                with pytest.raises(AccessDeniedError):
                    await storage.seal(update.id, StorageActor.VERIFIER)
                await storage.seal(update.id, StorageActor.DOWNLOADER)
                await storage.set_verification_result(update.id, False, StorageActor.VERIFIER)
                await session.commit()
                for actor in (StorageActor.VERIFIER, StorageActor.INSTALLER):
                    with pytest.raises(AccessDeniedError):
                        await storage.read(update.id, actor)
                with pytest.raises(AccessDeniedError):
                    await storage.set_verification_result(update.id, True, StorageActor.VERIFIER)
                await storage.cleanup(update.id, StorageActor.MANAGER)
                await session.commit()
        finally:
            if product_id is not None:
                await remove_test_product(product_id)
            await engine.dispose()

    asyncio.run(exercise())


def test_http_download_and_events():
    async def exercise():
        await engine.dispose()
        product_id = None
        update_id = None
        try:
            async with AsyncClient(transport=ASGITransport(app=app), base_url="http://test") as client:
                created = await client.post("/products", json={"name": f"block-b-api-{uuid4().hex}", "target": "test"},
                                            headers={"X-Registry-Role": "publisher"})
                assert created.status_code == 201
                product_id = UUID(created.json()["id"])
                published = await client.post(f"/products/{product_id}/packages", data={"version": "1.0"},
                                              files={"file": ("test.pkg", b"http-data")}, headers={"X-Registry-Role": "publisher"})
                assert published.status_code == 201
                device_payload = {"name": f"api-device-{uuid4().hex}", "product_id": str(product_id), "target": "test"}
                device = await client.post("/devices", json=device_payload)
                assert device.status_code == 201
                assert (await client.post("/devices", json=device_payload)).status_code == 409
                device_id = device.json()["id"]
                result = await client.post(f"/devices/{device_id}/updates/download")
                assert result.status_code == 201, result.text
                update_id = UUID(result.json()["id"])
                assert result.json()["state"] == "VERIFYING"
                assert result.json()["temporary_storage"]["state"] == "SEALED"
                assert (await client.get(f"/updates/{update_id}")).json()["temporary_storage"]["bytes_written"] == 9
                events = (await client.get(f"/updates/{update_id}/events")).json()
                assert events[-1]["event_type"] == "STORAGE_SEALED"
                assert (await client.post(f"/devices/{device_id}/updates/download")).status_code == 409
                state = (await client.get(f"/devices/{device_id}")).json()
                assert state["current_package_id"] is None
        finally:
            if update_id:
                TemporaryFileStore().delete(f"temporary/{update_id.hex}.pkg")
            if product_id:
                for key in await remove_test_product(product_id):
                    ServerFileStore().delete(key)
            await engine.dispose()

    asyncio.run(exercise())
