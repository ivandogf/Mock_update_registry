"""Safe local storage for published package bytes."""

import os
import base64
import json
import tempfile
from dataclasses import dataclass
from pathlib import Path
from uuid import UUID

from app.config import STORAGE_ROOT


class ServerFileStore:
    def __init__(self, root: Path = STORAGE_ROOT) -> None:
        self.root = root.resolve()
        self.server_dir = self.root / "server"

    def _path(self, storage_key: str) -> Path:
        path = (self.root / storage_key).resolve()
        if not path.is_relative_to(self.server_dir) or path == self.server_dir:
            raise ValueError("Invalid server storage key")
        return path

    def save(self, package_id: UUID, content: bytes) -> str:
        storage_key = f"server/{package_id.hex}.pkg"
        destination = self._path(storage_key)
        self.server_dir.mkdir(parents=True, exist_ok=True)
        temp_path: Path | None = None
        try:
            with tempfile.NamedTemporaryFile(dir=self.server_dir, delete=False) as temp_file:
                temp_path = Path(temp_file.name)
                temp_file.write(content)
            os.replace(temp_path, destination)
        finally:
            if temp_path is not None:
                temp_path.unlink(missing_ok=True)
        return storage_key

    def read(self, storage_key: str) -> bytes:
        return self._path(storage_key).read_bytes()

    def delete(self, storage_key: str) -> None:
        self._path(storage_key).unlink(missing_ok=True)


@dataclass(frozen=True)
class TemporaryBundle:
    content: bytes
    manifest_bytes: bytes
    signature: bytes
    signing_key_id: str


class BundleReadError(ValueError):
    """The payload or manifest cannot be read from temporary storage."""


class TemporaryFileStore:
    def __init__(self, root: Path = STORAGE_ROOT) -> None:
        self.root = root.resolve()
        self.directory = self.root / "temporary"

    def _path(self, key: str) -> Path:
        path = (self.root / key).resolve()
        if path.parent != self.directory or path.suffix != ".pkg":
            raise ValueError("Invalid temporary storage key")
        return path

    def create(self, session_id: UUID, manifest: bytes, signature: bytes, key_id: str) -> str:
        key = f"temporary/{session_id.hex}.pkg"
        path = self._path(key)
        self.directory.mkdir(parents=True, exist_ok=True)
        with path.open("xb"):
            pass
        try:
            with path.with_suffix(".meta").open("x", encoding="utf-8") as file:
                json.dump({
                    "manifest": base64.b64encode(manifest).decode("ascii"),
                    "signature": base64.b64encode(signature).decode("ascii"),
                    "signing_key_id": key_id,
                }, file)
        except BaseException:
            path.unlink(missing_ok=True)
            raise
        return key

    def append(self, key: str, content: bytes, expected_size: int) -> None:
        with self._path(key).open("r+b") as file:
            file.seek(0, os.SEEK_END)
            if file.tell() != expected_size:
                raise ValueError("Temporary file size differs from stored byte count")
            try:
                file.write(content)
                file.flush()
            except BaseException:
                file.truncate(expected_size)
                raise

    def size(self, key: str) -> int:
        return self._path(key).stat().st_size

    def read(self, key: str) -> TemporaryBundle:
        path = self._path(key)
        try:
            content = path.read_bytes()
            metadata = json.loads(path.with_suffix(".meta").read_text(encoding="utf-8"))
            manifest = base64.b64decode(metadata["manifest"], validate=True)
        except (OSError, ValueError, KeyError, TypeError) as exc:
            raise BundleReadError("Temporary payload or manifest is missing or malformed") from exc
        try:
            signature = base64.b64decode(metadata["signature"], validate=True)
        except (ValueError, KeyError, TypeError):
            # Keep hash verification first; malformed signatures fail its next stage.
            signature = b""
        return TemporaryBundle(
            content=content,
            manifest_bytes=manifest,
            signature=signature,
            signing_key_id=metadata.get("signing_key_id", ""),
        )

    def delete(self, key: str) -> None:
        path = self._path(key)
        path.unlink(missing_ok=True)
        path.with_suffix(".meta").unlink(missing_ok=True)


class DeviceFileStore:
    """Local installed copies, isolated by device and installation session."""

    def __init__(self, root: Path = STORAGE_ROOT) -> None:
        self.root = root.resolve()
        self.directory = self.root / "devices"

    @staticmethod
    def storage_key(device_id: UUID, session_id: UUID) -> str:
        return f"devices/{device_id.hex}/{session_id.hex}.pkg"

    def _path(self, key: str, device_id: UUID) -> Path:
        device_dir = (self.directory / device_id.hex).resolve()
        path = (self.root / key).resolve()
        if not device_dir.is_relative_to(self.directory) or path.parent != device_dir or path.suffix != ".pkg":
            raise ValueError("Invalid device storage key")
        return path

    def save(self, device_id: UUID, session_id: UUID, content: bytes) -> str:
        key = self.storage_key(device_id, session_id)
        destination = self._path(key, device_id)
        destination.parent.mkdir(parents=True, exist_ok=True)
        if destination.exists():
            raise FileExistsError("This installation session already has a local copy")
        staging: Path | None = None
        try:
            with tempfile.NamedTemporaryFile(dir=destination.parent, prefix="install-", delete=False) as file:
                staging = Path(file.name)
                file.write(content)
                file.flush()
                os.fsync(file.fileno())
            os.replace(staging, destination)
        finally:
            if staging is not None:
                staging.unlink(missing_ok=True)
        return key

    def read(self, key: str, device_id: UUID) -> bytes:
        return self._path(key, device_id).read_bytes()

    def delete(self, key: str, device_id: UUID) -> None:
        self._path(key, device_id).unlink(missing_ok=True)
