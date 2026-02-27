import json
import os
from pathlib import Path

from dotenv import load_dotenv

load_dotenv()

OLLAMA_BASE_URL = os.getenv("OLLAMA_BASE_URL", "http://localhost:11434")
OLLAMA_API_KEY = os.getenv("OLLAMA_API_KEY", "")
OLLAMA_MODEL = os.getenv("OLLAMA_MODEL", "llama3")
OLLAMA_TIMEOUT = int(os.getenv("OLLAMA_TIMEOUT", "120"))

REDIS_URL = os.getenv("REDIS_URL", "redis://localhost:6379")
DEDUP_WINDOW = int(os.getenv("DEDUP_WINDOW", "300"))
MIN_LEVEL = int(os.getenv("MIN_LEVEL", "8"))

_AGENTS_FILE = os.getenv("AGENTS_FILE", "agents.json")


def load_agents() -> dict:
    path = Path(_AGENTS_FILE)
    if not path.exists():
        return {}
    with open(path) as f:
        return json.load(f)
