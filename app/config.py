"""Application configuration for the local training environment."""

import os
from pathlib import Path

from dotenv import load_dotenv

load_dotenv()
DATABASE_URL = os.getenv("DATABASE_URL")
if not DATABASE_URL:
    raise RuntimeError("DATABASE_URL не задан. Добавьте его в .env файл.")

STORAGE_ROOT = Path("storage")
SERVER_TRUSTED = True
