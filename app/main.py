"""FastAPI entry point. Feature routers are added in later stages."""

from fastapi import FastAPI

from app.api import devices, packages, updates

app = FastAPI(title="Mock Update Registry", version="0.1.0")
app.include_router(packages.router)
app.include_router(devices.router)
app.include_router(updates.router)


@app.get("/health", tags=["System"])
async def health() -> dict[str, str]:
    return {"status": "ok"}
