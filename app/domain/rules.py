"""Basic access rules. These roles model permissions, not user identity."""

from enum import StrEnum

from app.domain.enums import TemporaryStorageState, UpdateSessionState


class RegistryRole(StrEnum):
    PUBLISHER = "publisher"
    DEVICE = "device"


class RegistryAction(StrEnum):
    CREATE_PRODUCT = "create_product"
    PUBLISH_PACKAGE = "publish_package"
    READ_RELEASE = "read_release"


class AccessDeniedError(Exception):
    pass


_ALLOWED = {
    RegistryAction.CREATE_PRODUCT: {RegistryRole.PUBLISHER},
    RegistryAction.PUBLISH_PACKAGE: {RegistryRole.PUBLISHER},
    RegistryAction.READ_RELEASE: {RegistryRole.PUBLISHER, RegistryRole.DEVICE},
}


def require_access(role: RegistryRole, action: RegistryAction) -> None:
    if role not in _ALLOWED[action]:
        raise AccessDeniedError(f"Role {role.value!r} cannot perform {action.value!r}")


class StorageActor(StrEnum):
    DOWNLOADER = "downloader"
    VERIFIER = "verifier"
    INSTALLER = "installer"
    MANAGER = "manager"


class InvalidTransitionError(Exception):
    pass


def require_storage_access(actor: StorageActor, operation: str, state: str) -> None:
    allowed = {
        "write": actor == StorageActor.DOWNLOADER and state == TemporaryStorageState.WRITE,
        "seal": actor == StorageActor.DOWNLOADER and state == TemporaryStorageState.WRITE,
        "read": (
            actor == StorageActor.VERIFIER and state in {TemporaryStorageState.SEALED, TemporaryStorageState.VERIFIED}
        ) or (actor == StorageActor.INSTALLER and state == TemporaryStorageState.VERIFIED),
        "verify": actor == StorageActor.VERIFIER and state == TemporaryStorageState.SEALED,
        "cleanup": actor == StorageActor.MANAGER or (
            actor == StorageActor.DOWNLOADER and state == TemporaryStorageState.WRITE
        ),
    }
    if not allowed.get(operation, False):
        raise AccessDeniedError(f"{actor.value} cannot {operation} storage in {state}")


def require_storage_transition(source: str, target: str) -> None:
    allowed = {
        TemporaryStorageState.WRITE: {TemporaryStorageState.SEALED},
        TemporaryStorageState.SEALED: {TemporaryStorageState.VERIFIED, TemporaryStorageState.REJECTED},
    }
    if target not in allowed.get(source, set()):
        raise InvalidTransitionError(f"Invalid storage transition: {source} -> {target}")


def require_update_transition(source: str, target: str) -> None:
    allowed = {
        "IDLE": {"CHECKING", "FAILED"},
        "CHECKING": {"DOWNLOADING", "NO_UPDATE", "FAILED"},
        "DOWNLOADING": {"VERIFYING", "FAILED"},
        "VERIFYING": {"INSTALLING", "REJECTED", "FAILED"},
        "INSTALLING": {"COMPLETED", "FAILED", "ROLLING_BACK"},
        "COMPLETED": {"ROLLING_BACK"},
        "FAILED": {"ROLLING_BACK"},
        "ROLLING_BACK": {"ROLLED_BACK", "FAILED"},
    }
    if target not in allowed.get(source, set()):
        raise InvalidTransitionError(f"Invalid update transition: {source} -> {target}")


ACTIVE_UPDATE_STATES = {
    UpdateSessionState.IDLE, UpdateSessionState.CHECKING, UpdateSessionState.DOWNLOADING,
    UpdateSessionState.VERIFYING, UpdateSessionState.INSTALLING, UpdateSessionState.ROLLING_BACK,
}
