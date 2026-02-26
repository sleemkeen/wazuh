import json
import os
from pathlib import Path

OLLAMA_BASE_URL = os.getenv("OLLAMA_BASE_URL", "http://localhost:11434")
OLLAMA_MODEL = os.getenv("OLLAMA_MODEL", "llama3")
OLLAMA_TIMEOUT = int(os.getenv("OLLAMA_TIMEOUT", "120"))

_AGENTS_FILE = os.getenv("AGENTS_FILE", "agents.json")


def load_agents() -> dict:
    path = Path(_AGENTS_FILE)
    if not path.exists():
        return {}
    with open(path) as f:
        return json.load(f)
