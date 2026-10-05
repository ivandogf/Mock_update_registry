"""Training faults use the real verifier/manager and devices installed by the normal flow."""

import asyncio
from uuid import UUID, uuid4

import pytest
from httpx import ASGITransport, AsyncClient
from sqlalchemy import select

from app.db.models import DeviceState, DeviceTrustedPackage, Package, ServerReleaseHead, TemporaryStorage, UpdateSession
from app.db.session import SessionFactory, engine
from app.domain.enums import ScenarioType
from app.domain.rules import StorageActor
from app.infrastructure.crypto import TrainingSigner
from app.infrastructure.files import DeviceFileStore, ServerFileStore, TemporaryFileStore
from app.infrastructure.trusted_keys import TrustedPublicKeyStore
from app.main import app
from app.services.downloader import DownloadConflict
from app.services.monitor import MonitorService
from app.services.scenarios import ScenarioConflict, ScenarioService
from tests.test_block_b import remove_test_product
from tests.test_block_d import assert_device, device_rig


EXPECTED_CHECKS = {
    ScenarioType.CORRUPTED_PACKAGE: ["HASH_INVALID", "PACKAGE_REJECTED", "STORAGE_CLEANED"],
    ScenarioType.INVALID_SIGNATURE: ["HASH_VALID", "SIGNATURE_INVALID", "PACKAGE_REJECTED", "STORAGE_CLEANED"],
    ScenarioType.OUTDATED_VERSION: ["HASH_VALID", "SIGNATURE_VALID", "TARGET_VALID", "VERSION_INVALID", "PACKAGE_REJECTED", "STORAGE_CLEANED"],
    ScenarioType.INSTALLATION_FAILURE: [
        "HASH_VALID", "SIGNATURE_VALID", "TARGET_VALID", "VERSION_VALID", "PACKAGE_VERIFIED",
        "INSTALL_STARTED", "INSTALL_FAILED", "ROLLBACK_STARTED", "ROLLBACK_COMPLETED", "STORAGE_CLEANED",
    ],
}


def scenario_service(rig):
    return ScenarioService(
        rig.session, gateway=rig.manager.downloader.gateway, storage=rig.storage,
        files=rig.files, trusted_keys=rig.manager.verifier.trusted_keys,
    )


@pytest.mark.parametrize("scenario", list(ScenarioType))
def test_scenario_inputs_actual_checks_and_request_isolation(tmp_path, monkeypatch, scenario):
    async def exercise():
        async with device_rig(tmp_path) as rig:
            first, _ = await rig.install_release("1.0")
            current, _ = await rig.install_release("2.0")
            newest = await rig.publish("3.0")
            first_id, current_id, newest_id = first.id, current.id, newest.id
            originals = {p.id: (p.manifest_bytes, p.signature, p.sha256_hex) for p in (first, current, newest)}
            reads = []
            downloaded_bundles = {}
            actual_read = rig.storage.read

            async def observe_read(session_id, actor):
                row = await rig.session.get(TemporaryStorage, session_id)
                reads.append((actor, row.state))
                bundle = await actual_read(session_id, actor)
                downloaded_bundles[session_id] = bundle
                return bundle

            monkeypatch.setattr(rig.storage, "read", observe_read)
            monkeypatch.setattr(TrainingSigner, "_private_key", lambda *args: pytest.fail("Scenario used a private signing key"))
            result = await scenario_service(rig).run(rig.device_id, scenario)
            update_id = result.id
            assert result.scenario_type == scenario.value
            assert result.state == ("ROLLED_BACK" if scenario == ScenarioType.INSTALLATION_FAILURE else "REJECTED")
            selected_id = first_id if scenario == ScenarioType.OUTDATED_VERSION else newest_id
            assert result.target_package_id == selected_id
            assert result.scenario_config["selected_package_id"] == str(selected_id)
            assert result.scenario_config["current_version"] == "2.0"
            assert result.scenario_config["protection"]
            assert result.original_current_package_id == current_id
            assert result.original_fallback_package_id == first_id
            await assert_device(rig, current_id, first_id, trusted_ids=[first_id, current_id])
            async with SessionFactory() as observer:
                persisted = await observer.get(UpdateSession, update_id)
                assert persisted.scenario_config == result.scenario_config
                assert persisted.scenario_type == scenario.value
                events = await MonitorService(observer).events_for_session(update_id)
                assert events[0].event_type == "SCENARIO_STARTED"
                assert events[0].component == "ScenarioService"
                assert events[0].details == dict(result.scenario_config, scenario_type=scenario.value)
                assert [e.event_type for e in events if e.event_type.startswith("SCENARIO_")] == ["SCENARIO_STARTED"]
                assert [e.event_type for e in events[1:7]] == [
                    "UPDATE_CHECK_STARTED", "UPDATE_FOUND", "DOWNLOAD_STARTED", "STORAGE_CREATED",
                    "DOWNLOAD_COMPLETED", "STORAGE_SEALED",
                ]
                assert [e.event_type for e in events[7:]] == EXPECTED_CHECKS[scenario]
                heads = await observer.get(ServerReleaseHead, rig.product_id)
                assert (heads.current_package_id, heads.fallback_package_id) == (newest_id, current_id)
                row = await observer.get(TemporaryStorage, update_id)
                assert row.state == ("VERIFIED" if scenario == ScenarioType.INSTALLATION_FAILURE else "REJECTED")
                assert row.cleaned_at is not None
                path = tmp_path / row.storage_key
                assert not path.exists() and not path.with_suffix(".meta").exists()
                bundle = downloaded_bundles[update_id]
                payload = bundle.content
                assert bundle.manifest_bytes == originals[selected_id][0]
                if scenario == ScenarioType.INVALID_SIGNATURE:
                    assert bundle.signature != originals[selected_id][1]
                else:
                    assert bundle.signature == originals[selected_id][1]
                assert (payload == (b"1.0" if selected_id == first_id else b"3.0")) == (scenario != ScenarioType.CORRUPTED_PACKAGE)
                for package_id, original in originals.items():
                    stored = await observer.get(Package, package_id)
                    assert (stored.manifest_bytes, stored.signature, stored.sha256_hex) == original
                if scenario == ScenarioType.INSTALLATION_FAILURE:
                    assert persisted.verification_result == "PASSED"
                    assert persisted.failure_code == "INSTALLATION_FAILED"
                    assert await observer.get(DeviceTrustedPackage, (rig.device_id, newest_id)) is None
                    assert not (tmp_path / rig.files.storage_key(rig.device_id, update_id)).exists()
                else:
                    assert persisted.verification_result == next(event for event in EXPECTED_CHECKS[scenario] if event.endswith("_INVALID"))
            assert reads == [(StorageActor.VERIFIER, "SEALED")] + (
                [(StorageActor.INSTALLER, "VERIFIED")] if scenario == ScenarioType.INSTALLATION_FAILURE else []
            )
            # The injected operation is scoped to this request. The same published
            # release still downloads, verifies and installs normally afterwards.
            normal = await rig.manager.run(rig.device_id)
            assert normal.state == "COMPLETED"
            assert normal.scenario_type is None and normal.scenario_config is None
            await assert_device(rig, newest_id, current_id, trusted_ids=[first_id, current_id, newest_id])

    asyncio.run(exercise())


def test_outdated_current_version_is_really_downloaded(tmp_path, monkeypatch):
    async def exercise():
        async with device_rig(tmp_path) as rig:
            current, _ = await rig.install_release("1.0")
            current_id = current.id
            raw_manifest, signature = current.manifest_bytes, current.signature
            bundles = []
            original_read = rig.storage.read

            async def observe_download(*args):
                bundle = await original_read(*args)
                bundles.append(bundle)
                return bundle

            monkeypatch.setattr(rig.storage, "read", observe_download)
            result = await scenario_service(rig).run(rig.device_id, ScenarioType.OUTDATED_VERSION)
            assert result.state == "REJECTED" and result.verification_result == "VERSION_INVALID"
            assert result.target_package_id == current_id
            row = await rig.session.get(TemporaryStorage, result.id)
            assert row.cleaned_at is not None and not (tmp_path / row.storage_key).exists()
            assert len(bundles) == 1
            bundle = bundles[0]
            assert bundle.manifest_bytes == raw_manifest and bundle.signature == signature
            assert bundle.content == b"1.0"
            await assert_device(rig, current_id, None, trusted_ids=[current_id])

    asyncio.run(exercise())


@pytest.mark.parametrize("scenario", [ScenarioType.OUTDATED_VERSION, ScenarioType.INSTALLATION_FAILURE])
def test_scenario_requires_installed_current_without_creating_seed(tmp_path, scenario):
    async def exercise():
        async with device_rig(tmp_path) as rig:
            await rig.publish("1.0")
            with pytest.raises(ScenarioConflict, match="previously successfully installed"):
                await scenario_service(rig).run(rig.device_id, scenario)
            await assert_device(rig, None, None, trusted_ids=[])
            async with SessionFactory() as observer:
                assert await observer.scalar(select(UpdateSession.id).where(UpdateSession.device_id == rig.device_id)) is None

    asyncio.run(exercise())


def test_installation_failure_requires_newer_release(tmp_path):
    async def exercise():
        async with device_rig(tmp_path) as rig:
            current, _ = await rig.install_release("1.0")
            current_id = current.id
            with pytest.raises(ScenarioConflict, match="newer than device current"):
                await scenario_service(rig).run(rig.device_id, ScenarioType.INSTALLATION_FAILURE)
            await assert_device(rig, current_id, None, trusted_ids=[current_id])

    asyncio.run(exercise())


def test_scenario_cannot_start_during_an_active_update(tmp_path):
    async def exercise():
        async with device_rig(tmp_path) as rig:
            await rig.install_release("1.0")
            await rig.publish("2.0")
            active = await rig.manager.downloader.download(rig.device_id)
            active_id = active.id
            with pytest.raises(DownloadConflict):
                await scenario_service(rig).run(rig.device_id, ScenarioType.CORRUPTED_PACKAGE)
            async with SessionFactory() as observer:
                update = await observer.get(UpdateSession, active_id)
                assert update.state == "VERIFYING" and update.scenario_type is None
                assert not any(e.event_type == "SCENARIO_STARTED" for e in await MonitorService(observer).events_for_session(active_id))

    asyncio.run(exercise())


@pytest.mark.parametrize("scenario", list(ScenarioType))
def test_http_scenario_endpoint(tmp_path, monkeypatch, scenario):
    async def exercise():
        await engine.dispose()
        product_id = device_id = None
        update_ids = []
        trust = TrustedPublicKeyStore(tmp_path / "trusted_keys")
        monkeypatch.setattr("app.services.verifier.TrustedPublicKeyStore", lambda: trust)
        monkeypatch.setattr("app.services.scenarios.TrustedPublicKeyStore", lambda: trust)
        try:
            async with AsyncClient(transport=ASGITransport(app=app), base_url="http://test") as client:
                created = await client.post("/products", json={"name": f"scenario-api-{uuid4().hex}", "target": "test"},
                                            headers={"Role": "publisher"})
                assert created.status_code == 201
                product_id = UUID(created.json()["id"])
                published = await client.post(f"/products/{product_id}/packages", data={"version": "1.0"},
                                              files={"file": ("first.pkg", b"first")}, headers={"Role": "publisher"})
                assert published.status_code == 201
                trust.provision(TrainingSigner().public_key_bytes())
                created_device = await client.post("/devices", json={"name": f"scenario-device-{uuid4().hex}",
                                                                    "product_id": str(product_id), "target": "test"})
                assert created_device.status_code == 201
                device_id = UUID(created_device.json()["id"])
                path = f"/devices/{device_id}/scenarios/{scenario.value}/run"
                if scenario in {ScenarioType.OUTDATED_VERSION, ScenarioType.INSTALLATION_FAILURE}:
                    assert (await client.post(path)).status_code == 409
                installed = await client.post(f"/devices/{device_id}/updates/run")
                assert installed.status_code == 201 and installed.json()["state"] == "COMPLETED"
                update_ids.append(UUID(installed.json()["id"]))
                if scenario != ScenarioType.OUTDATED_VERSION:
                    newer = await client.post(f"/products/{product_id}/packages", data={"version": "2.0"},
                                              files={"file": ("second.pkg", b"second")}, headers={"Role": "publisher"})
                    assert newer.status_code == 201
                result = await client.post(path)
                assert result.status_code == 201, result.text
                body = result.json()
                update_id = UUID(body["id"])
                update_ids.append(update_id)
                assert body["state"] == ("ROLLED_BACK" if scenario == ScenarioType.INSTALLATION_FAILURE else "REJECTED")
                assert body["scenario_type"] == scenario.value
                assert body["scenario_config"]["protection"]
                assert body["temporary_storage"]["cleaned_at"] is not None
                persisted = (await client.get(f"/updates/{update_id}")).json()
                assert persisted["scenario_config"] == body["scenario_config"]
                events = (await client.get(f"/updates/{update_id}/events")).json()
                assert events[0]["event_type"] == "SCENARIO_STARTED"
                assert [e["event_type"] for e in events[7:]] == EXPECTED_CHECKS[scenario]
                state = (await client.get(f"/devices/{device_id}")).json()
                assert state["current_package_id"] == published.json()["id"] and state["fallback_package_id"] is None
                assert (await client.post(f"/devices/{device_id}/scenarios/UNKNOWN/run")).status_code == 422
                assert (await client.post(f"/devices/{uuid4()}/scenarios/{scenario.value}/run")).status_code == 404
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
