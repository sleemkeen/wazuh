import json
import logging
import re

import httpx

from .config import OLLAMA_API_KEY, OLLAMA_BASE_URL, OLLAMA_MODEL, OLLAMA_TIMEOUT

log = logging.getLogger("soc")

SYSTEM_PROMPT = """\
You are a SOC security analyst AI. You receive Wazuh SIEM alerts and respond with a remediation plan.

Given an alert and the target OS, you MUST return ONLY a JSON object with these fields:

{
  "action": "IGNORE | BLOCK_IP | DISABLE_ACCOUNT | KILL_PROCESS | REVERT_CONFIG",
  "severity": "low | medium | high | critical",
  "summary": "one-line explanation",
  "reason": "why you chose this action",
  "script": "the exact shell script to run on the target (bash for ubuntu, powershell for windows). empty string if action is IGNORE."
}

RULES:
- Level 0-4  → IGNORE
- Level 5-7  → investigate, act if suspicious
- Level 8+   → remediate
- Brute force / scanning           → BLOCK_IP
- Privilege escalation / sudo abuse → DISABLE_ACCOUNT
- Malware / crypto miner            → KILL_PROCESS
- Persistence / config tampering    → REVERT_CONFIG
- Benign or unclear                 → IGNORE

SCRIPT RULES:
- For ubuntu: write a bash script
- For windows: write a powershell script
- The script must be safe, focused, and only address the specific threat
- Include a verification step at the end (e.g. check the rule was added, user was locked, process is dead)
- If action is IGNORE, set script to ""

Return ONLY valid JSON. No markdown. No explanation outside the JSON.
"""


async def ask_ollama(alert: dict, target_os: str) -> dict:
    user_msg = json.dumps({"alert": alert, "target_os": target_os}, indent=2)
    payload = {
        "model": OLLAMA_MODEL,
        "messages": [
            {"role": "system", "content": SYSTEM_PROMPT},
            {"role": "user", "content": user_msg},
        ],
        "stream": False,
        "format": "json",
        "options": {"temperature": 0.1, "num_predict": 2048},
    }

    headers = {}
    if OLLAMA_API_KEY:
        headers["Authorization"] = f"Bearer {OLLAMA_API_KEY}"

    async with httpx.AsyncClient(timeout=OLLAMA_TIMEOUT) as client:
        resp = await client.post(f"{OLLAMA_BASE_URL}/api/chat", json=payload, headers=headers)
        resp.raise_for_status()

    raw = resp.json().get("message", {}).get("content", "")
    text = raw.strip()
    text = re.sub(r"^```(?:json)?\s*", "", text)
    text = re.sub(r"\s*```$", "", text)
    return json.loads(text)
