"""Audit events written in the same transaction as registry changes."""

from typing import Any
from uuid import UUID

from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession

from app.db.models import AuditEvent


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
