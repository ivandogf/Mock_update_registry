"""Scoped training faults; verification, installation and rollback use the normal services."""

import base64
import json
from uuid import UUID

from packaging.version import InvalidVersion, Version
from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession

from app.db.models import Device, DeviceState, Package, TemporaryStorage, UpdateSession
from app.domain.enums import ScenarioType
from app.domain.rules import RegistryRole
from app.infrastructure.files import DeviceFileStore, TemporaryFileStore
from app.infrastructure.trusted_keys import TrustedPublicKeyStore
from app.services.downloader import DownloaderService
from app.services.gateway import ExternalNetworkGateway
from app.services.installer import InstallationError, InstallerService
from app.services.monitor import MonitorService
from app.services.packages import NoPublishedRelease, RegistryNotFound, UpdateServerService
from app.services.temporary_storage import TemporaryStorageService
from app.services.update_manager import UpdateManagerService
from app.services.verifier import VerifierService


class ScenarioConflict(Exception):
    pass


_DESCRIPTIONS = {
    ScenarioType.CORRUPTED_PACKAGE: {
        "protection": "Контроль целостности скачанного файла по SHA-256",
        "injection": "После загрузки изменяется один байт .pkg без изменения размера и manifest",
    },
    ScenarioType.INVALID_SIGNATURE: {
        "protection": "Подлинность manifest: Ed25519 и заранее доверенный public key",
        "injection": "Изменяется только подпись; файл пакета и точные байты manifest сохранены",
    },
    ScenarioType.OUTDATED_VERSION: {
        "protection": "Запрет установки версии, которая не новее текущей версии устройства",
        "injection": "Выбирается настоящий опубликованный подписанный пакет с версией <= current",
    },
    ScenarioType.INSTALLATION_FAILURE: {
        "protection": "Автоматический откат к исходным доверенным локальным current/fallback",
        "injection": "Ошибка операции сохранения пакета на устройство",
    },
}


class _TemporaryFileFaults(TemporaryFileStore):
    """Simulate external damage to backing files; this is not authorized Storage WRITE.

    Only ScenarioService uses this adapter, while locking a SEALED training session.
    Storage actors and their access rules are unchanged.
    """

    def corrupt_package(self, key: str) -> None:
        with self._path(key).open("r+b") as file:
            original = file.read(1)
            if not original:
                raise ScenarioConflict("Cannot corrupt an empty downloaded package")
            file.seek(0)
            file.write(bytes([original[0] ^ 1]))

    def corrupt_signature(self, key: str) -> None:
        path = self._path(key).with_suffix(".meta")
        metadata = json.loads(path.read_text(encoding="utf-8"))
        signature = base64.b64decode(metadata["signature"], validate=True)
        if not signature:
            raise ScenarioConflict("Downloaded signature is missing")
        metadata["signature"] = base64.b64encode(bytes([signature[0] ^ 1]) + signature[1:]).decode("ascii")
        path.write_text(json.dumps(metadata), encoding="utf-8")


class _FailingInstallationFiles(DeviceFileStore):
    def save(self, device_id: UUID, session_id: UUID, content: bytes) -> str:
        # Real copy operation fails before the installer creates trust records or pointers.
        super().save(device_id, session_id, content)
        raise InstallationError("Учебный сценарий: искусственная ошибка сохранения установленного пакета")


class ScenarioService:
    def __init__(
        self, session: AsyncSession, gateway: ExternalNetworkGateway | None = None,
        storage: TemporaryStorageService | None = None, files: DeviceFileStore | None = None,
        trusted_keys: TrustedPublicKeyStore | None = None,
    ) -> None:
        self.session = session
        self.gateway = gateway or ExternalNetworkGateway(UpdateServerService(session))
        self.storage = storage or TemporaryStorageService(session)
        self.files = files or DeviceFileStore()
        self.trusted_keys = trusted_keys or TrustedPublicKeyStore()
        self.monitor = MonitorService(session)

    async def _select_package(self, device: Device, scenario: ScenarioType) -> tuple[Package, str | None]:
        state = await self.session.get(DeviceState, device.id, populate_existing=True)
        current = (
            await self.session.get(Package, state.current_package_id, populate_existing=True)
            if state is not None and state.current_package_id is not None else None
        )
        if scenario in {ScenarioType.OUTDATED_VERSION, ScenarioType.INSTALLATION_FAILURE} and current is None:
            raise ScenarioConflict(f"{scenario.value} requires a previously successfully installed current package")
        try:
            current_version = Version(current.version) if current else None
            # Read local registry metadata to choose the scenario input. The Downloader
            # still fetches that release exclusively through the Gateway and its trust checks.
            registry = UpdateServerService(self.session)
            if scenario == ScenarioType.OUTDATED_VERSION:
                published = await registry.list_packages(device.product_id, RegistryRole.DEVICE)
                candidates = [(Version(package.version), package) for package in published
                              if package.target == device.target and Version(package.version) <= current_version]
                if not candidates:
                    raise ScenarioConflict("No published package with version <= device current is available")
                # Prefer a genuinely older release; equality is valid when only current exists.
                older = [candidate for candidate in candidates if candidate[0] < current_version]
                selected = max(older or candidates, key=lambda candidate: candidate[0])[1]
            else:
                selected = await registry.latest(device.product_id, RegistryRole.DEVICE)
                if scenario == ScenarioType.INSTALLATION_FAILURE and Version(selected.version) <= current_version:
                    raise ScenarioConflict("INSTALLATION_FAILURE requires a published version newer than device current")
        except InvalidVersion as exc:
            raise ScenarioConflict("Published/device versions must be valid PEP 440 versions") from exc
        except NoPublishedRelease as exc:
            raise ScenarioConflict("Publish a package before running this scenario") from exc
        return selected, current.version if current else None

    async def _damage_download(self, update_id: UUID, scenario: ScenarioType) -> None:
        # Share Verifier's lock order so a concurrently verified package cannot be damaged.
        row = await self.session.scalar(
            select(TemporaryStorage).where(TemporaryStorage.session_id == update_id)
            .with_for_update().execution_options(populate_existing=True)
        )
        update = await self.session.get(UpdateSession, update_id, populate_existing=True)
        if (row is None or row.state != "SEALED" or row.cleaned_at is not None
                or update is None or update.state != "VERIFYING" or update.scenario_type != scenario.value):
            raise ScenarioConflict("File fault injection requires this scenario's SEALED downloaded package")
        faults = _TemporaryFileFaults(self.storage.files.root)
        if scenario == ScenarioType.CORRUPTED_PACKAGE:
            faults.corrupt_package(row.storage_key)
        else:
            faults.corrupt_signature(row.storage_key)
        await self.session.commit()

    async def run(self, device_id: UUID, scenario_type: ScenarioType) -> UpdateSession:
        scenario = ScenarioType(scenario_type)
        try:
            # Keep the device snapshot stable through selection and session creation.
            device = await self.session.get(Device, device_id, with_for_update=True, populate_existing=True)
            if device is None:
                raise RegistryNotFound("Device not found")
            package, current_version = await self._select_package(device, scenario)
            config = dict(_DESCRIPTIONS[scenario], selected_package_id=str(package.id),
                          selected_version=package.version, current_version=current_version)

            def started(update: UpdateSession) -> None:
                update.scenario_type = scenario.value
                update.scenario_config = config
                self.monitor.record(
                    "SCENARIO_STARTED", f"Учебный сценарий {scenario.value}: {config['protection']}",
                    component="ScenarioService", session_id=update.id,
                    details=dict(config, scenario_type=scenario.value),
                )

            downloader = DownloaderService(self.session, self.gateway, self.storage, on_session_started=started)
            update = await downloader.download(device_id, package_id=package.id)
            if update.state != "VERIFYING":
                return update
            if scenario in {ScenarioType.CORRUPTED_PACKAGE, ScenarioType.INVALID_SIGNATURE}:
                await self._damage_download(update.id, scenario)
            update = await VerifierService(self.session, self.storage, self.trusted_keys).verify(update.id)
            if update.verification_result != "PASSED":
                return update
            files = _FailingInstallationFiles(self.files.root) if scenario == ScenarioType.INSTALLATION_FAILURE else self.files
            manager = UpdateManagerService(self.session, InstallerService(self.session, self.storage, files))
            return await manager.install(update.id)
        except Exception:
            await self.session.rollback()
            raise
