"""Audit events written in the same transaction as registry changes."""

from typing import Any
from uuid import UUID

from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncConnection, AsyncSession

from app.db.models import AuditEvent, UpdateSession
from app.domain.rules import AccessDeniedError, RegistryAction, RegistryRole, require_access


class MonitorService:
    def __init__(self, session: AsyncSession) -> None:
        self.session = session

    def record(
        self,
        event_type: str,
        message: str,
        *,
        component: str,
        level: str = "INFO",
        session_id: UUID | None = None,
        details: dict[str, Any] | None = None,
    ) -> None:
        self.session.add(
            AuditEvent(
                session_id=session_id,
                event_type=event_type,
                component=component,
                level=level,
                message=message,
                details=details or {},
            )
        )

    async def events_for_session(self, session_id: UUID) -> list[AuditEvent]:
        result = await self.session.execute(
            select(AuditEvent)
            .where(AuditEvent.session_id == session_id)
            .order_by(AuditEvent.created_at, AuditEvent.id)
        )
        return list(result.scalars())

    async def access_denied(
        self,
        session_id: UUID | None = None,
        *,
        actor: str,
        operation: str,
        message: str,
        storage_state: str | None = None,
        component: str = "TemporaryStorageService",
        details: dict[str, Any] | None = None,
    ) -> None:
        """Persist a denial independently so a caller rollback does not erase it."""
        bind = self.session.bind
        if isinstance(bind, AsyncConnection):
            bind = bind.engine
        if bind is None:
            raise RuntimeError("Audit requires a database connection")
        event_details = dict(details or {})
        event_details.update(actor=actor, operation=operation)
        if session_id is not None:
            event_details["session_id"] = str(session_id)
        if storage_state is not None:
            event_details["storage_state"] = storage_state
        async with AsyncSession(bind=bind) as audit_session:
            # A new session may not yet be committed in the caller's transaction.
            # Keep its ID in details without creating an invisible foreign-key reference.
            committed_session = (
                await audit_session.get(UpdateSession, session_id) if session_id is not None else None
            )
            MonitorService(audit_session).record(
                "ACCESS_DENIED",
                message,
                component=component,
                level="WARNING",
                session_id=session_id if committed_session is not None else None,
                details=event_details,
            )
            await audit_session.commit()

    async def require_access(
        self, role: RegistryRole, action: RegistryAction, *,
        component: str, details: dict[str, Any] | None = None,
    ) -> None:
        """Apply domain policy and persist exactly one event on rejection."""
        try:
            require_access(role, action)
        except AccessDeniedError as exc:
            await self.access_denied(
                actor=role.value, operation=action.value, message=str(exc),
                component=component, details=details,
            )
            raise
