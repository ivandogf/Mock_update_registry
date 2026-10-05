"""Verifier checks against local PostgreSQL; only test-created records are removed."""

import asyncio
import base64
import json
from datetime import datetime, timezone
from uuid import UUID, uuid4

import pytest
from httpx import ASGITransport, AsyncClient
from sqlalchemy import select

from app.db.models import Device, DeviceState, DeviceTrustedPackage, TemporaryStorage
from app.db.session import SessionFactory, engine
from app.domain.rules import AccessDeniedError, RegistryRole, StorageActor
from app.infrastructure.crypto import TrainingSigner
from app.infrastructure.files import ServerFileStore, TemporaryFileStore
from app.infrastructure.trusted_keys import TrustedPublicKeyStore, UntrustedSigningKey
from app.main import app
from app.services.downloader import DownloaderService
from app.services.gateway import ExternalNetworkGateway
from app.services.monitor import MonitorService
from app.services.packages import PackageRegistryService, UpdateServerService
from app.services.temporary_storage import TemporaryStorageService
from app.services.verifier import VerifierService
from tests.test_block_b import remove_test_product


CASES = [
    ("success", "PASSED"),
    ("first_package", "PASSED"),
    ("corrupted", "HASH_INVALID"),
    ("truncated", "HASH_INVALID"),
    ("missing_payload", "HASH_INVALID"),
    ("malformed_manifest", "HASH_INVALID"),
    ("duplicate_manifest_field", "HASH_INVALID"),
    ("invalid_signature", "SIGNATURE_INVALID"),
    ("malformed_signature", "SIGNATURE_INVALID"),
    ("changed_manifest", "SIGNATURE_INVALID"),
    ("unknown_key", "SIGNATURE_INVALID"),
    ("key_id_mismatch", "SIGNATURE_INVALID"),
    ("wrong_target", "TARGET_INVALID"),
    ("wrong_product", "TARGET_INVALID"),
    ("wrong_package", "TARGET_INVALID"),
    ("equal_version", "VERSION_INVALID"),
    ("older_version", "VERSION_INVALID"),
    ("malformed_version", "VERSION_INVALID"),
    ("missing_version", "VERSION_INVALID"),
    ("invalid_current_version", "VERSION_INVALID"),
]


@pytest.mark.parametrize("mode,expected", CASES)
def test_verifier_checks_and_audit(tmp_path, monkeypatch, mode, expected):
    async def exercise():
        await engine.dispose()
        product_id = None
        try:
            async with SessionFactory() as session:
                server_files = ServerFileStore(tmp_path)
                signer = TrainingSigner(tmp_path / "server.key")
                trust = TrustedPublicKeyStore(tmp_path / "trusted_keys")
                trust.provision(signer.public_key_bytes())
                registry = PackageRegistryService(session, server_files, signer)
                product = await registry.create_product(f"block-c-{uuid4().hex}", "linux-x64", RegistryRole.PUBLISHER)
                product_id = product.id
                current = await registry.publish_package(product_id, "1.9", "old.pkg", b"old", RegistryRole.PUBLISHER)
                package = await registry.publish_package(product_id, "1.10", "new.pkg", b"new-package", RegistryRole.PUBLISHER)
                device_id = uuid4()
                session.add(Device(id=device_id, name=f"verifier-device-{device_id.hex}", product_id=product_id, target=product.target))
                await session.flush()
                current_id = None
                if mode != "first_package":
                    current_id = current.id
                    session.add(DeviceTrustedPackage(
                        device_id=device_id, package_id=current_id,
                        local_storage_key=f"devices/{device_id.hex}/old.pkg",
                        verified_sha256_hex=current.sha256_hex, verified_at=datetime.now(timezone.utc),
                    ))
                    await session.flush()
                session.add(DeviceState(device_id=device_id, current_package_id=current_id))
                await session.commit()
                files = TemporaryFileStore(tmp_path)
                storage = TemporaryStorageService(session, files)
                gateway = ExternalNetworkGateway(UpdateServerService(session, server_files))
                update = await DownloaderService(session, gateway, storage).download(device_id)
                update_id = update.id
                row = await session.get(TemporaryStorage, update_id)
                payload_path = tmp_path / row.storage_key
                metadata_path = payload_path.with_suffix(".meta")
                metadata = json.loads(metadata_path.read_text(encoding="utf-8"))
                manifest = json.loads(package.manifest_bytes)
                if mode == "corrupted":
                    payload_path.write_bytes(b"bad-package")  # Same size, different hash.
                elif mode == "truncated":
                    payload_path.write_bytes(b"bad")
                elif mode == "missing_payload":
                    payload_path.unlink()
                elif mode == "malformed_manifest":
                    metadata["manifest"] = base64.b64encode(b"{invalid-json").decode("ascii")
                elif mode == "duplicate_manifest_field":
                    raw = package.manifest_bytes[:-1] + b',"version":"9.0"}'
                    metadata["manifest"] = base64.b64encode(raw).decode("ascii")
                    metadata["signature"] = base64.b64encode(signer.sign(raw)).decode("ascii")
                elif mode == "invalid_signature":
                    metadata["signature"] = base64.b64encode(b"x" * 64).decode("ascii")
                elif mode == "malformed_signature":
                    metadata["signature"] = "not base64!"
                elif mode == "key_id_mismatch":
                    metadata["signing_key_id"] = "ed25519-" + "0" * 16
                elif mode == "invalid_current_version":
                    current.version = "invalid"
                    await session.commit()
                elif mode in {"changed_manifest", "unknown_key", "wrong_target", "wrong_product", "wrong_package",
                              "equal_version", "older_version", "malformed_version", "missing_version"}:
                    signing_key = signer
                    if mode == "unknown_key":
                        signing_key = TrainingSigner(tmp_path / "attacker.key")
                        metadata["signing_key_id"] = signing_key.key_id()
                        manifest["signing_key_id"] = signing_key.key_id()
                        metadata["public_key"] = base64.b64encode(signing_key.public_key_bytes()).decode("ascii")
                    elif mode in {"wrong_target", "changed_manifest"}:
                        manifest["target"] = "another-platform"
                    elif mode == "wrong_product":
                        manifest["product_id"] = str(uuid4())
                    elif mode == "wrong_package":
                        manifest["package_id"] = str(uuid4())
                    elif mode == "missing_version":
                        del manifest["version"]
                    else:
                        manifest["version"] = {"equal_version": "1.9.0", "older_version": "1.8", "malformed_version": "oops"}[mode]
                    raw = json.dumps(manifest, sort_keys=True, separators=(",", ":")).encode()
                    metadata["manifest"] = base64.b64encode(raw).decode("ascii")
                    if mode != "changed_manifest":
                        metadata["signature"] = base64.b64encode(signing_key.sign(raw)).decode("ascii")
                metadata_path.write_text(json.dumps(metadata), encoding="utf-8")

                def forbidden_private_key(_self):
                    raise AssertionError("Verifier must never read a private signing key")

                monkeypatch.setattr(TrainingSigner, "_private_key", forbidden_private_key)
                verified = await VerifierService(session, storage, trust).verify(update_id)
                assert verified.verification_result == expected
                assert verified.original_current_package_id == current_id
                assert verified.original_fallback_package_id is None
                # Verify durable transitions/events from a separate connection.
                async with SessionFactory() as observer:
                    stored = await observer.get(TemporaryStorage, update_id)
                    state = await observer.get(DeviceState, device_id)
                    assert state.current_package_id == current_id and state.fallback_package_id is None
                    assert len(list(await observer.scalars(select(DeviceTrustedPackage).where(
                        DeviceTrustedPackage.device_id == device_id,
                    )))) == (0 if current_id is None else 1)
                    events = [e.event_type for e in await MonitorService(observer).events_for_session(update_id)]
                    if expected == "PASSED":
                        assert stored.state == "VERIFIED" and stored.verified_at is not None
                        assert verified.state == "VERIFYING" and verified.failure_code is None
                        assert verified.finished_at is None
                        assert events[6:] == ["HASH_VALID", "SIGNATURE_VALID", "TARGET_VALID", "VERSION_VALID", "PACKAGE_VERIFIED"]
                    else:
                        assert stored.state == "REJECTED" and stored.verified_at is None
                        assert verified.state == "REJECTED" and verified.failure_code == expected
                        assert verified.finished_at is not None
                        order = ["HASH", "SIGNATURE", "TARGET", "VERSION"]
                        failed_index = order.index(expected.removesuffix("_INVALID"))
                        assert events[6:] == [f"{check}_VALID" for check in order[:failed_index]] + [expected, "PACKAGE_REJECTED"]
                with pytest.raises(AccessDeniedError):
                    await VerifierService(session, storage, trust).verify(update_id)
                async with SessionFactory() as observer:
                    events = await MonitorService(observer).events_for_session(update_id)
                    assert events[-1].event_type == "ACCESS_DENIED"
                    assert events[-1].details["actor"] == "verifier"
                    assert events[-1].details["storage_state"] == ("VERIFIED" if expected == "PASSED" else "REJECTED")
        finally:
            if product_id is not None:
                await remove_test_product(product_id)
            await engine.dispose()

    asyncio.run(exercise())


@pytest.mark.parametrize("expected", ["PASSED", "HASH_INVALID", "SIGNATURE_INVALID"])
def test_http_verify(tmp_path, monkeypatch, expected):
    async def exercise():
        await engine.dispose()
        product_id = update_id = None
        trust = TrustedPublicKeyStore(tmp_path / "trusted_keys")
        # HTTP uses an isolated pre-provisioned store, not the user's trust configuration.
        monkeypatch.setattr("app.services.verifier.TrustedPublicKeyStore", lambda: trust)
        try:
            async with AsyncClient(transport=ASGITransport(app=app), base_url="http://test") as client:
                created = await client.post("/products", json={"name": f"block-c-api-{uuid4().hex}", "target": "test"},
                                            headers={"X-Registry-Role": "publisher"})
                assert created.status_code == 201
                product_id = UUID(created.json()["id"])
                published = await client.post(f"/products/{product_id}/packages", data={"version": "1.0"},
                                              files={"file": ("test.pkg", b"http-data")}, headers={"X-Registry-Role": "publisher"})
                assert published.status_code == 201
                if expected != "SIGNATURE_INVALID":
                    trust.provision(TrainingSigner().public_key_bytes())
                device = await client.post("/devices", json={"name": f"api-verifier-{uuid4().hex}",
                                                            "product_id": str(product_id), "target": "test"})
                assert device.status_code == 201
                downloaded = await client.post(f"/devices/{device.json()['id']}/updates/download")
                assert downloaded.status_code == 201
                update_id = UUID(downloaded.json()["id"])
                if expected == "HASH_INVALID":
                    (TemporaryFileStore().root / f"temporary/{update_id.hex}.pkg").write_bytes(b"bad-data!")
                verified = await client.post(f"/updates/{update_id}/verify")
                assert verified.status_code == 200, verified.text
                assert verified.json()["verification_result"] == expected
                assert verified.json()["temporary_storage"]["state"] == ("VERIFIED" if expected == "PASSED" else "REJECTED")
                events = (await client.get(f"/updates/{update_id}/events")).json()
                assert events[-1]["event_type"] == ("PACKAGE_VERIFIED" if expected == "PASSED" else "PACKAGE_REJECTED")
                assert (await client.post(f"/updates/{update_id}/verify")).status_code == 409
                assert (await client.post(f"/updates/{uuid4()}/verify")).status_code == 404
                state = (await client.get(f"/devices/{device.json()['id']}")).json()
                assert state["current_package_id"] is None and state["fallback_package_id"] is None
        finally:
            if update_id is not None:
                TemporaryFileStore().delete(f"temporary/{update_id.hex}.pkg")
            if product_id is not None:
                for key in await remove_test_product(product_id):
                    ServerFileStore().delete(key)
            await engine.dispose()

    asyncio.run(exercise())


def test_trusted_public_key_store(tmp_path):
    signer = TrainingSigner(tmp_path / "signing.key")
    trust = TrustedPublicKeyStore(tmp_path / "trusted")
    raw = signer.public_key_bytes()
    key_id = trust.provision(raw)
    assert trust.provision(raw) == key_id
    trust.get(key_id).verify(signer.sign(b"original bytes"), b"original bytes")
    for invalid_id in ("../../server/signing_key.raw", "ed25519-" + "0" * 16, None):
        with pytest.raises(UntrustedSigningKey):
            trust.get(invalid_id)
    (trust.directory / f"{key_id}.pub").write_bytes(TrainingSigner(tmp_path / "other.key").public_key_bytes())
    with pytest.raises(UntrustedSigningKey):
        trust.get(key_id)
