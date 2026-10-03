"""Local server adapter with simulated server trust and network failure."""

from uuid import UUID

from app.config import SERVER_TRUSTED
from app.db.models import Package
from app.domain.rules import RegistryRole
from app.services.packages import UpdateServerService


class GatewayError(Exception):
    pass


class UntrustedServerError(GatewayError):
    pass


class NetworkUnavailableError(GatewayError):
    pass


class ExternalNetworkGateway:
    """Downloader-facing interface; replace internals with HTTP/HTTPS later."""

    def __init__(
        self,
        server: UpdateServerService,
        *,
        server_trusted: bool = SERVER_TRUSTED,
        network_available: bool = True,
    ) -> None:
        self.server = server
        self.server_trusted = server_trusted
        self.network_available = network_available

    def _check_connection(self) -> None:
        if not self.network_available:
            raise NetworkUnavailableError("Update server is unavailable")
        if not self.server_trusted:
            raise UntrustedServerError("Update server is not trusted")

    async def latest(self, product_id: UUID) -> Package:
        self._check_connection()
        return await self.server.latest(product_id, RegistryRole.DEVICE)

    async def manifest(self, package_id: UUID) -> Package:
        self._check_connection()
        return await self.server.manifest(package_id, RegistryRole.DEVICE)

    async def download(self, package_id: UUID) -> tuple[Package, bytes]:
        self._check_connection()
        return await self.server.download(package_id, RegistryRole.DEVICE)
