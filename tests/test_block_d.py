"""Prepare rollback devices by real successful installations, without demo seed data."""

import asyncio
from contextlib import asynccontextmanager
from datetime import datetime, timezone
from types import SimpleNamespace
from unittest.mock import AsyncMock
from uuid import UUID, uuid4

import pytest
from httpx import ASGITransport, AsyncClient
from sqlalchemy import delete, select

from app.db.models import Device, DeviceState, DeviceTrustedPackage, ServerReleaseHead, TemporaryStorage, UpdateSession
from app.db.session import SessionFactory, engine
from app.domain.rules import AccessDeniedError, RegistryRole
from app.infrastructure.crypto import TrainingSigner
from app.infrastructure.files import DeviceFileStore, ServerFileStore, TemporaryFileStore
from app.infrastructure.trusted_keys import TrustedPublicKeyStore
from app.main import app
from app.services.downloader import DownloaderService
from app.services.gateway import ExternalNetworkGateway
from app.services.installer import InstallerService
from app.services.monitor import MonitorService
from app.services.packages import PackageRegistryService, UpdateServerService
from app.services.temporary_storage import TemporaryStorageService
from app.services.update_manager import UpdateConflict, UpdateManagerService
from app.services.verifier import VerifierService
from tests.test_block_b import remove_test_product


@asynccontextmanager
async def device_rig(tmp_path):
    await engine.dispose()
    product_id = None
    try:
        async with SessionFactory() as session:
            signer = TrainingSigner(tmp_path / "test.key")
            trust = TrustedPublicKeyStore(tmp_path / "trusted_keys")
            trust.provision(signer.public_key_bytes())
            server_files = ServerFileStore(tmp_path)
            device_files = DeviceFileStore(tmp_path)
            storage = TemporaryStorageService(session, TemporaryFileStore(tmp_path))
            registry = PackageRegistryService(session, server_files, signer)
            product = await registry.create_product(f"block-d-{uuid4().hex}", "test", RegistryRole.PUBLISHER)
            product_id = product.id
            device_id = uuid4()
            session.add(Device(id=device_id, name=f"block-d-device-{device_id.hex}", product_id=product_id, target="test"))
            await session.flush()
            session.add(DeviceState(device_id=device_id))
            await session.commit()
            downloader = DownloaderService(session, ExternalNetworkGateway(UpdateServerService(session, server_files)), storage)
            verifier = VerifierService(session, storage, trust)
            manager = UpdateManagerService(
                session, InstallerService(session, storage, device_files), downloader=downloader, verifier=verifier,
            )

            async def publish(version):
                return await registry.publish_package(product_id, version, "test.pkg", version.encode(), RegistryRole.PUBLISHER)

            async def install_release(version):
                package = await publish(version)
                update = await manager.run(device_id)
                assert update.state == "COMPLETED"
                return package, update

            async def verified_release(version):
                package = await publish(version)
                update = await downloader.download(device_id)
                update = await verifier.verify(update.id)
                assert update.verification_result == "PASSED"
                return package, update

            yield SimpleNamespace(
                session=session, product_id=product_id, device_id=device_id, manager=manager,
                storage=storage, files=device_files, install_release=install_release,
                verified_release=verified_release, publish=publish,
            )
    finally:
        if product_id is not None:
            await remove_test_product(product_id)
        await engine.dispose()


async def assert_device(rig, current_id, fallback_id, *, trusted_ids):
    async with SessionFactory() as observer:
        state = await observer.get(DeviceState, rig.device_id)
        assert (state.current_package_id, state.fallback_package_id) == (current_id, fallback_id)
        copies = list(await observer.scalars(select(DeviceTrustedPackage).where(
            DeviceTrustedPackage.device_id == rig.device_id,
        )))
        assert {copy.package_id for copy in copies} == set(trusted_ids)
        for copy in copies:
            assert rig.files.read(copy.local_storage_key, rig.device_id)


async def event_types(session_id):
    async with SessionFactory() as observer:
        return [event.event_type for event in await MonitorService(observer).events_for_session(session_id)]


def prevent_network(monkeypatch):
    async def blocked(*args, **kwargs):
        raise AssertionError("Rollback must not contact the server")

    for method in ("latest", "manifest", "download"):
        monkeypatch.setattr(ExternalNetworkGateway, method, blocked)


def test_install_and_offline_rollback_preserve_both_originals(tmp_path, monkeypatch):
    async def exercise():
        async with device_rig(tmp_path) as rig:
            first, first_update = await rig.install_release("1.0")
            await assert_device(rig, first.id, None, trusted_ids=[first.id])
            assert (await event_types(first_update.id))[-3:] == ["INSTALL_STARTED", "DEVICE_CURRENT_UPDATED", "INSTALL_COMPLETED"]
            second = await rig.publish("2.0")
            # Publishing changes only server heads; the device still has version 1.0.
            await assert_device(rig, first.id, None, trusted_ids=[first.id])
            second_update = await rig.manager.run(rig.device_id)
            assert second_update.state == "COMPLETED"
            await assert_device(rig, second.id, first.id, trusted_ids=[first.id, second.id])
            third, third_update = await rig.install_release("3.0")
            third_update_id = third_update.id
            assert third_update.original_current_package_id == second.id
            assert third_update.original_fallback_package_id == first.id
            await assert_device(rig, third.id, second.id, trusted_ids=[first.id, second.id, third.id])
            prevent_network(monkeypatch)
            # Rollback must not read Temporary Storage either.
            monkeypatch.setattr(TemporaryFileStore, "read", lambda *args: pytest.fail("Rollback read temporary storage"))
            rolled = await rig.manager.rollback(third_update_id)
            assert rolled.state == "ROLLED_BACK" and rolled.failure_code is None
            await assert_device(rig, second.id, first.id, trusted_ids=[first.id, second.id, third.id])
            assert (await event_types(third_update_id))[-2:] == ["ROLLBACK_STARTED", "ROLLBACK_COMPLETED"]
            async with SessionFactory() as observer:
                heads = await observer.get(ServerReleaseHead, rig.product_id)
                assert (heads.current_package_id, heads.fallback_package_id) == (third.id, second.id)

    asyncio.run(exercise())


@pytest.mark.parametrize("failure", ["before_copy", "after_copy", "after_db_changes"])
def test_automatic_rollback_uses_successfully_installed_current(tmp_path, monkeypatch, failure):
    async def exercise():
        async with device_rig(tmp_path) as rig:
            first, _ = await rig.install_release("1.0")
            current, _ = await rig.install_release("2.0")
            target, update = await rig.verified_release("3.0")
            update_id = update.id
            prevent_network(monkeypatch)
            observed_uncommitted = []

            class FailingFiles(DeviceFileStore):
                def save(self, device_id, session_id, content):
                    if failure == "after_copy":
                        super().save(device_id, session_id, content)
                    raise OSError("Test installation copy failure")

            class FailingInstaller(InstallerService):
                async def install(self, update):
                    await super().install(update)
                    # Even after flush, other connections must not see this as installed/trusted.
                    async with SessionFactory() as observer:
                        state = await observer.get(DeviceState, rig.device_id)
                        trusted = await observer.get(DeviceTrustedPackage, (rig.device_id, target.id))
                        observed_uncommitted.append((state.current_package_id, trusted))
                    raise RuntimeError("Test failure after local copy and DB changes")

            files = FailingFiles(tmp_path) if failure != "after_db_changes" else rig.files
            installer_class = FailingInstaller if failure == "after_db_changes" else InstallerService
            manager = UpdateManagerService(rig.session, installer_class(rig.session, rig.storage, files))
            result = await manager.install(update_id)
            assert result.state == "ROLLED_BACK" and result.failure_code == "INSTALLATION_FAILED"
            assert result.finished_at is not None
            if failure == "after_db_changes":
                assert observed_uncommitted == [(current.id, None)]
            await assert_device(rig, current.id, first.id, trusted_ids=[first.id, current.id])
            assert not (tmp_path / rig.files.storage_key(rig.device_id, update_id)).exists()
            assert (await event_types(update_id))[11:] == [
                "INSTALL_STARTED", "INSTALL_FAILED", "ROLLBACK_STARTED", "ROLLBACK_COMPLETED",
            ]

    asyncio.run(exercise())


@pytest.mark.parametrize("damage,expected", [
    ("missing_current", "ROLLBACK_LOCAL_COPY_UNAVAILABLE"),
    ("corrupted_fallback", "ROLLBACK_HASH_MISMATCH"),
])
def test_failed_install_and_impossible_rollback(tmp_path, damage, expected):
    async def exercise():
        async with device_rig(tmp_path) as rig:
            first, _ = await rig.install_release("1.0")
            current, _ = await rig.install_release("2.0")
            target, update = await rig.verified_release("3.0")
            update_id = update.id
            damaged_id = current.id if damage == "missing_current" else first.id
            damaged = await rig.session.get(DeviceTrustedPackage, (rig.device_id, damaged_id))
            original_bytes = rig.files.read(damaged.local_storage_key, rig.device_id)
            damaged_path = tmp_path / damaged.local_storage_key
            if damage == "missing_current":
                damaged_path.unlink()
            else:
                damaged_path.write_bytes(b"corrupted")

            class FailingFiles(DeviceFileStore):
                def save(self, device_id, session_id, content):
                    super().save(device_id, session_id, content)
                    raise OSError("Test installation failure")

            result = await UpdateManagerService(
                rig.session, InstallerService(rig.session, rig.storage, FailingFiles(tmp_path)),
            ).install(update_id)
            assert result.state == "FAILED" and result.failure_code == expected
            assert not (tmp_path / rig.files.storage_key(rig.device_id, update_id)).exists()
            assert (await event_types(update_id))[-4:] == ["INSTALL_STARTED", "INSTALL_FAILED", "ROLLBACK_STARTED", "ROLLBACK_FAILED"]
            async with SessionFactory() as observer:
                assert await observer.get(DeviceTrustedPackage, (rig.device_id, target.id)) is None
                state = await observer.get(DeviceState, rig.device_id)
                assert (state.current_package_id, state.fallback_package_id) == (current.id, first.id)
            # Retry restoration after fixing the local copy; no network/seed is needed.
            damaged_path.write_bytes(original_bytes)
            result = await rig.manager.rollback(update_id)
            assert result.state == "ROLLED_BACK"
            await assert_device(rig, current.id, first.id, trusted_ids=[first.id, current.id])

    asyncio.run(exercise())


def test_missing_original_trust_record_rejects_manual_rollback(tmp_path):
    async def exercise():
        async with device_rig(tmp_path) as rig:
            first, _ = await rig.install_release("1.0")
            second, _ = await rig.install_release("2.0")
            third, update = await rig.install_release("3.0")
            update_id = update.id
            # Original fallback is no longer in the current device pointers, so its
            # trust record can be removed while preserving the schema's foreign keys.
            await rig.session.execute(delete(DeviceTrustedPackage).where(
                DeviceTrustedPackage.device_id == rig.device_id, DeviceTrustedPackage.package_id == first.id,
            ))
            await rig.session.commit()
            result = await rig.manager.rollback(update_id)
            assert result.state == "FAILED" and result.failure_code == "ROLLBACK_PACKAGE_NOT_TRUSTED"
            await assert_device(rig, third.id, second.id, trusted_ids=[second.id, third.id])
            assert (await event_types(update_id))[-2:] == ["ROLLBACK_STARTED", "ROLLBACK_FAILED"]

    asyncio.run(exercise())


@pytest.mark.parametrize("condition", ["session_state", "verification", "storage_state", "cleaned", "snapshot"])
def test_installation_guards_audit_denial(tmp_path, condition):
    async def exercise():
        async with device_rig(tmp_path) as rig:
            package, update = await rig.verified_release("1.0")
            update_id = update.id
            row = await rig.session.get(TemporaryStorage, update_id)
            if condition == "session_state":
                update.state = "CHECKING"
            elif condition == "verification":
                update.verification_result = None
            elif condition == "storage_state":
                row.state = "SEALED"
            elif condition == "cleaned":
                row.cleaned_at = datetime.now(timezone.utc)
            else:
                update.original_current_package_id = package.id
            await rig.session.commit()
            with pytest.raises(UpdateConflict):
                await rig.manager.install(update_id)
            await assert_device(rig, None, None, trusted_ids=[])
            events = await event_types(update_id)
            assert events[-1] == "ACCESS_DENIED" and "INSTALL_STARTED" not in events
            assert not (tmp_path / rig.files.storage_key(rig.device_id, update_id)).exists()

    asyncio.run(exercise())


@pytest.mark.parametrize("state,result", [("VERIFYING", "PASSED"), ("INSTALLING", None)])
def test_installer_checks_session_before_reading_storage(tmp_path, monkeypatch, state, result):
    async def exercise():
        async with device_rig(tmp_path) as rig:
            _, update = await rig.verified_release("1.0")
            update_id = update.id
            update.state = state
            update.verification_result = result
            await rig.session.commit()
            read = AsyncMock(wraps=rig.storage.read)
            monkeypatch.setattr(rig.storage, "read", read)
            with pytest.raises(AccessDeniedError):
                await InstallerService(rig.session, rig.storage, rig.files).install(update)
            read.assert_not_awaited()
            await rig.session.rollback()
            async with SessionFactory() as observer:
                events = await MonitorService(observer).events_for_session(update_id)
                assert events[-1].event_type == "ACCESS_DENIED"
                assert events[-1].component == "InstallerService"
                assert events[-1].details["operation"] == "install"
            await assert_device(rig, None, None, trusted_ids=[])

    asyncio.run(exercise())


def test_first_installation_failure_restores_empty_device(tmp_path):
    async def exercise():
        async with device_rig(tmp_path) as rig:
            _, update = await rig.verified_release("1.0")

            class FailingFiles(DeviceFileStore):
                def save(self, *args):
                    raise OSError("No space for the first installation")

            result = await UpdateManagerService(
                rig.session, InstallerService(rig.session, rig.storage, FailingFiles(tmp_path)),
            ).install(update.id)
            assert result.state == "ROLLED_BACK"
            await assert_device(rig, None, None, trusted_ids=[])

    asyncio.run(exercise())


def test_old_session_rollback_cannot_overwrite_newer_install(tmp_path):
    async def exercise():
        async with device_rig(tmp_path) as rig:
            first, update = await rig.install_release("1.0")
            first_id = first.id
            old_update_id = update.id
            second, _ = await rig.install_release("2.0")
            second_id = second.id
            with pytest.raises(UpdateConflict):
                await rig.manager.rollback(old_update_id)
            await assert_device(rig, second_id, first_id, trusted_ids=[first_id, second_id])
            assert (await event_types(old_update_id))[-1] == "ACCESS_DENIED"

    asyncio.run(exercise())


def test_concurrent_install_is_applied_once(tmp_path):
    async def exercise():
        async with device_rig(tmp_path) as rig:
            package, update = await rig.verified_release("1.0")
            update_id = update.id

            async def install_once():
                async with SessionFactory() as session:
                    manager = UpdateManagerService(session, InstallerService(
                        session, TemporaryStorageService(session, TemporaryFileStore(tmp_path)), DeviceFileStore(tmp_path),
                    ))
                    try:
                        return (await manager.install(update_id)).state
                    except UpdateConflict:
                        return "CONFLICT"

            results = await asyncio.wait_for(asyncio.gather(install_once(), install_once()), timeout=10)
            assert sorted(results) == ["COMPLETED", "CONFLICT"]
            await assert_device(rig, package.id, None, trusted_ids=[package.id])
            events = await event_types(update_id)
            assert events.count("INSTALL_STARTED") == events.count("INSTALL_COMPLETED") == 1
            assert events[-1] == "ACCESS_DENIED"

    asyncio.run(exercise())


def test_http_run_install_and_rollback(tmp_path, monkeypatch):
    async def exercise():
        await engine.dispose()
        product_id = None
        update_ids = []
        device_id = None
        trust = TrustedPublicKeyStore(tmp_path / "trusted_keys")
        monkeypatch.setattr("app.services.verifier.TrustedPublicKeyStore", lambda: trust)
        try:
            async with AsyncClient(transport=ASGITransport(app=app), base_url="http://test") as client:
                response = await client.post("/products", json={"name": f"block-d-api-{uuid4().hex}", "target": "test"},
                                             headers={"X-Registry-Role": "publisher"})
                assert response.status_code == 201
                product_id = UUID(response.json()["id"])
                first = await client.post(f"/products/{product_id}/packages", data={"version": "1.0"},
                                          files={"file": ("test.pkg", b"first")}, headers={"X-Registry-Role": "publisher"})
                assert first.status_code == 201
                trust.provision(TrainingSigner().public_key_bytes())
                response = await client.post("/devices", json={"name": f"block-d-api-device-{uuid4().hex}",
                                                              "product_id": str(product_id), "target": "test"})
                assert response.status_code == 201
                device_id = UUID(response.json()["id"])
                result = await client.post(f"/devices/{device_id}/updates/run")
                assert result.status_code == 201, result.text
                update_ids.append(UUID(result.json()["id"]))
                assert result.json()["state"] == "COMPLETED"
                second = await client.post(f"/products/{product_id}/packages", data={"version": "2.0"},
                                           files={"file": ("test.pkg", b"second")}, headers={"X-Registry-Role": "publisher"})
                assert second.status_code == 201
                downloaded = await client.post(f"/devices/{device_id}/updates/download")
                assert downloaded.status_code == 201
                update_id = UUID(downloaded.json()["id"])
                update_ids.append(update_id)
                assert (await client.post(f"/updates/{update_id}/install")).status_code == 409
                assert (await client.post(f"/updates/{update_id}/verify")).json()["verification_result"] == "PASSED"
                installed = await client.post(f"/updates/{update_id}/install")
                assert installed.status_code == 200 and installed.json()["state"] == "COMPLETED"
                assert (await client.post(f"/updates/{update_id}/install")).status_code == 409
                state = (await client.get(f"/devices/{device_id}")).json()
                assert (state["current_package_id"], state["fallback_package_id"]) == (second.json()["id"], first.json()["id"])
                rolled = await client.post(f"/updates/{update_id}/rollback")
                assert rolled.status_code == 200 and rolled.json()["state"] == "ROLLED_BACK"
                state = (await client.get(f"/devices/{device_id}")).json()
                assert state["current_package_id"] == first.json()["id"] and state["fallback_package_id"] is None
                events = (await client.get(f"/updates/{update_id}/events")).json()
                assert events[-1]["event_type"] == "ROLLBACK_COMPLETED"
                assert (await client.post(f"/updates/{uuid4()}/install")).status_code == 404
                assert (await client.post(f"/updates/{uuid4()}/rollback")).status_code == 404
        finally:
            for update_id in update_ids:
                TemporaryFileStore().delete(f"temporary/{update_id.hex}.pkg")
                if device_id is not None:
                    files = DeviceFileStore()
                    files.delete(files.storage_key(device_id, update_id), device_id)
            if product_id is not None:
                for key in await remove_test_product(product_id):
                    ServerFileStore().delete(key)
            await engine.dispose()

    asyncio.run(exercise())
