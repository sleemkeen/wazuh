import logging
from datetime import datetime, timezone

from fastapi import FastAPI
from fastapi.middleware.cors import CORSMiddleware
from pydantic import BaseModel, Field

from .config import OLLAMA_BASE_URL, OLLAMA_MODEL, load_agents
from .executor import run_ssh
from .llm import ask_ollama

logging.basicConfig(level=logging.INFO, format="%(asctime)s  %(levelname)-8s  %(message)s")
log = logging.getLogger("soc")

app = FastAPI(title="SOC Remediation", version="3.0.0")
app.add_middleware(CORSMiddleware, allow_origins=["*"], allow_methods=["*"], allow_headers=["*"])

AGENTS: dict = {}
AUDIT: list[dict] = []


@app.on_event("startup")
async def startup():
    global AGENTS
    AGENTS = load_agents()
    log.info("Loaded %d agent(s): %s", len(AGENTS), list(AGENTS.keys()))


class AlertRule(BaseModel):
    id: str = ""
    level: int = 0
    description: str = ""

class AlertAgent(BaseModel):
    name: str = ""

class WazuhAlert(BaseModel):
    timestamp: str = ""
    rule: AlertRule = Field(default_factory=AlertRule)
    agent: AlertAgent = Field(default_factory=AlertAgent)
    data: dict = Field(default_factory=dict)
    full_log: str = ""


@app.get("/health")
async def health():
    return {
        "status": "ok",
        "ollama": OLLAMA_BASE_URL,
        "model": OLLAMA_MODEL,
        "agents": list(AGENTS.keys()),
    }


@app.post("/webhook")
async def webhook(alert: WazuhAlert):
    agent_name = alert.agent.name
    agent = AGENTS.get(agent_name)
    target_os = agent.get("os", "ubuntu") if agent else "ubuntu"

    try:
        decision = await ask_ollama(alert.model_dump(), target_os)
    except Exception as e:
        log.error("Ollama failed: %s", e)
        decision = {
            "action": "IGNORE",
            "severity": "low",
            "summary": f"LLM error: {e}",
            "reason": "Ollama unavailable, defaulting to IGNORE.",
            "script": "",
        }

    action = decision.get("action", "IGNORE")
    script = decision.get("script", "")

    execution = {"executed": False, "output": "", "error": ""}

    if action != "IGNORE" and script and agent:
        execution = await run_ssh(
            host=agent["host"],
            port=agent.get("port", 22),
            username=agent["username"],
            script=script,
            password=agent.get("password"),
            key_file=agent.get("key_file"),
            target_os=target_os,
        )
        execution["executed"] = True
    elif action != "IGNORE" and not agent:
        execution["error"] = f"Agent '{agent_name}' not in inventory."

    AUDIT.append({
        "timestamp": datetime.now(timezone.utc).isoformat(),
        "agent": agent_name,
        "rule": alert.rule.description,
        "level": alert.rule.level,
        "action": action,
        "executed": execution.get("executed", False),
    })
    log.info("action=%s  executed=%s  agent=%s", action, execution.get("executed"), agent_name)

    return {
        "decision": decision,
        "agent": agent_name,
        "agent_os": target_os,
        "execution": execution,
    }


@app.post("/analyze")
async def analyze_only(alert: WazuhAlert):
    agent = AGENTS.get(alert.agent.name)
    target_os = agent.get("os", "ubuntu") if agent else "ubuntu"
    try:
        return await ask_ollama(alert.model_dump(), target_os)
    except Exception as e:
        return {"action": "IGNORE", "summary": f"LLM error: {e}", "script": ""}


@app.get("/audit")
async def audit():
    return list(reversed(AUDIT))
