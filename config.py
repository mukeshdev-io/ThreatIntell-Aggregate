"""
config.py
─────────
Central configuration: loads environment variables from .env and exposes
typed constants used by all other modules.
"""

import logging
import os
from pathlib import Path

from dotenv import load_dotenv

# Load .env from the project root (the directory that contains this file).
load_dotenv(Path(__file__).parent / ".env")

# ── API keys ──────────────────────────────────────────────────────────────────
VIRUSTOTAL_API_KEY: str = os.getenv("VIRUSTOTAL_API_KEY", "")
OTX_API_KEY: str = os.getenv("OTX_API_KEY", "")

# ── VirusTotal ────────────────────────────────────────────────────────────────
VT_BASE_URL: str = "https://www.virustotal.com/api/v3"
# Free tier: 4 requests / minute.  We stay conservative at 3 req/min.
VT_RATE_LIMIT_CALLS: int = 3
VT_RATE_LIMIT_PERIOD: int = 60  # seconds
VT_TIMEOUT: int = 30  # seconds per request
VT_MAX_RETRIES: int = 4

# ── AlienVault OTX ───────────────────────────────────────────────────────────
OTX_BASE_URL: str = "https://otx.alienvault.com"
OTX_TIMEOUT: int = 30
OTX_MAX_RETRIES: int = 4

# ── Database ──────────────────────────────────────────────────────────────────
DB_PATH: str = str(Path(__file__).parent / "threatintel.db")
CACHE_TTL_HOURS: int = 24  # hours before a cached result is considered stale

# ── Logging ───────────────────────────────────────────────────────────────────
LOG_LEVEL: str = os.getenv("LOG_LEVEL", "INFO")

logging.basicConfig(
    level=getattr(logging, LOG_LEVEL, logging.INFO),
    format="%(asctime)s [%(levelname)s] %(name)s – %(message)s",
    datefmt="%Y-%m-%dT%H:%M:%S",
)
