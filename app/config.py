import os
from pathlib import Path

try:
    from dotenv import load_dotenv
    load_dotenv()
except Exception:
    pass

LLM_BASE_URL = os.getenv("LLM_BASE_URL", "").rstrip("/")
LLM_API_KEY = os.getenv("LLM_API_KEY", "")
LLM_MODEL = os.getenv("LLM_MODEL", "")
LLM_PROVIDER = os.getenv("LLM_PROVIDER", "")
FAKE_LLM = os.getenv("FAKE_LLM") == "1"
PROFILE = "ga5-incident-agent/v2"
AGENT_DEADLINE_S = 15.0

DATA_DIR = Path(os.getenv("DATA_DIR", ""))
try:
    DATA_DIR.mkdir(parents=True, exist_ok=True)
except Exception:
    DATA_DIR = Path("/tmp/data")
    DATA_DIR.mkdir(parents=True, exist_ok=True)
DB_PATH = DATA_DIR / "incidents.db"