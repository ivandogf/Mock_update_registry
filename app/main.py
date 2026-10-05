"""FastAPI entry point for the training registry."""

from fastapi import FastAPI

from app.api import devices, packages, updates

app = FastAPI(
    title="Mock Update Registry",
    version="0.1.0",
    description=(
        "Учебный реестр обновлений. Для публикации укажите заголовок "
        "Role: publisher. Это модель роли, без проверки личности."
    ),
)
app.include_router(packages.router)
app.include_router(devices.router)
app.include_router(updates.router)


@app.get("/health", tags=["System"])
async def health() -> dict[str, str]:
    return {"status": "ok"}



#python -m uvicorn app.main:app --reload