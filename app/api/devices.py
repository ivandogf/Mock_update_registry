"""Mock devices for exercising the download flow."""

from typing import Annotated
from uuid import UUID, uuid4

from fastapi import APIRouter, Depends, HTTPException
from sqlalchemy.exc import IntegrityError
from sqlalchemy.ext.asyncio import AsyncSession

from app.api.schemas import DeviceCreate, DeviceRead
from app.db.models import Device, DeviceState, Product
from app.db.session import get_session

router = APIRouter(tags=["Devices"])


async def device_response(session: AsyncSession, device: Device) -> DeviceRead:
    state = await session.get(DeviceState, device.id)
    return DeviceRead(
        id=device.id, name=device.name, product_id=device.product_id, target=device.target,
        current_package_id=state.current_package_id if state else None,
        fallback_package_id=state.fallback_package_id if state else None,
    )


@router.post("/devices", response_model=DeviceRead, status_code=201)
async def create_device(payload: DeviceCreate, session: Annotated[AsyncSession, Depends(get_session)]):
    product = await session.get(Product, payload.product_id)
    if product is None:
        raise HTTPException(status_code=404, detail="Product not found")
    if payload.target != product.target:
        raise HTTPException(status_code=422, detail="Device target must match product target")
    name = payload.name.strip()
    if not name:
        raise HTTPException(status_code=422, detail="Device name is required")
    device = Device(id=uuid4(), name=name, product_id=product.id, target=payload.target)
    session.add(device)
    try:
        await session.flush()
        session.add(DeviceState(device_id=device.id))
        await session.commit()
    except IntegrityError as exc:
        await session.rollback()
        raise HTTPException(status_code=409, detail="Device name already exists") from exc
    return await device_response(session, device)


@router.get("/devices/{device_id}", response_model=DeviceRead)
async def get_device(device_id: UUID, session: Annotated[AsyncSession, Depends(get_session)]):
    device = await session.get(Device, device_id)
    if device is None:
        raise HTTPException(status_code=404, detail="Device not found")
    return await device_response(session, device)
