import logging
import time
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

# dedup: key = "agent|rule_id|srcip" → timestamp of last action
DEDUP_CACHE: dict[str, float] = {}
DEDUP_WINDOW = 300  # seconds — ignore duplicate incidents within 5 minutes


def _dedup_key(agent_name: str, rule_id: str, data: dict) -> str:
    srcip = data.get("srcip", data.get("src_ip", ""))
    user = data.get("dstuser", data.get("user", ""))
    return f"{agent_name}|{rule_id}|{srcip}|{user}"


def _is_duplicate(key: str) -> bool:
    last_seen = DEDUP_CACHE.get(key)
    if last_seen and (time.time() - last_seen) < DEDUP_WINDOW:
        return True
    return False


def _mark_seen(key: str):
    DEDUP_CACHE[key] = time.time()


@app.on_event("startup")
async def startup():
    global AGENTS
    AGENTS = load_agents()
    log.info("Loaded %d agent(s): %s", len(AGENTS), list(AGENTS.keys()))
    log.info("Ollama endpoint: %s  model: %s", OLLAMA_BASE_URL, OLLAMA_MODEL)
    log.info("Dedup window: %ds", DEDUP_WINDOW)


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
        "dedup_window_seconds": DEDUP_WINDOW,
        "dedup_active_keys": len(DEDUP_CACHE),
    }


@app.post("/webhook")
async def webhook(alert: WazuhAlert):
    agent_name = alert.agent.name
    agent = AGENTS.get(agent_name)
    target_os = agent.get("os", "ubuntu") if agent else "ubuntu"

    log.info("=" * 60)
    log.info("[STEP 1] ALERT RECEIVED")
    log.info("  Agent: '%s'  OS: %s", agent_name, target_os)
    if agent:
        log.info("  Agent FOUND in inventory → %s@%s", agent["username"], agent["host"])
    else:
        log.warning("  Agent '%s' NOT FOUND in inventory. Available: %s", agent_name, list(AGENTS.keys()))
    log.info("  Rule: [%s] %s (level %d)", alert.rule.id, alert.rule.description, alert.rule.level)
    log.info("  Log: %s", alert.full_log[:200])

    # ── Dedup check ────────────────────────────────────────────────
    key = _dedup_key(agent_name, alert.rule.id, alert.data)
    if _is_duplicate(key):
        log.info("[DEDUP] Duplicate incident — already handled within %ds. Skipping.", DEDUP_WINDOW)
        log.info("  Key: %s", key)
        log.info("=" * 60)
        return {
            "decision": {"action": "IGNORE", "reason": "Duplicate incident, already remediated."},
            "agent": agent_name,
            "agent_os": target_os,
            "execution": {"executed": False, "output": "", "error": ""},
            "deduplicated": True,
        }

    log.info("[STEP 2] SENDING TO OLLAMA (%s)...", OLLAMA_MODEL)
    try:
        decision = await ask_ollama(alert.model_dump(), target_os)
    except Exception as e:
        log.error("[STEP 2] OLLAMA FAILED: %s", e)
        decision = {
            "action": "IGNORE",
            "severity": "low",
            "summary": f"LLM error: {e}",
            "reason": "Ollama unavailable, defaulting to IGNORE.",
            "script": "",
        }

    action = decision.get("action", "IGNORE")
    script = decision.get("script", "")

    log.info("[STEP 3] AI DECISION")
    log.info("  Action:   %s", action)
    log.info("  Severity: %s", decision.get("severity", "?"))
    log.info("  Summary:  %s", decision.get("summary", "?"))
    log.info("  Reason:   %s", decision.get("reason", "?"))
    if script:
        log.info("  Script:   %s", script[:200])

    execution = {"executed": False, "output": "", "error": ""}

    if action != "IGNORE" and script and agent:
        log.info("[STEP 4] EXECUTING REMEDIATION via SSH on %s (%s)...", agent_name, agent["host"])
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

        if execution["success"]:
            log.info("[STEP 5] EXECUTION SUCCESS")
            log.info("  Output: %s", execution["output"][:300])
        else:
            log.error("[STEP 5] EXECUTION FAILED")
            log.error("  Error: %s", execution["error"][:300])

        _mark_seen(key)
        log.info("[DEDUP] Marked key for %ds cooldown: %s", DEDUP_WINDOW, key)
    elif action != "IGNORE" and not agent:
        log.warning("[STEP 4] SKIPPED — agent '%s' not in inventory", agent_name)
        execution["error"] = f"Agent '{agent_name}' not in inventory."
    else:
        log.info("[STEP 4] SKIPPED — action is IGNORE, nothing to execute")

    AUDIT.append({
        "timestamp": datetime.now(timezone.utc).isoformat(),
        "agent": agent_name,
        "rule": alert.rule.description,
        "level": alert.rule.level,
        "action": action,
        "executed": execution.get("executed", False),
    })

    log.info("[DONE] action=%s  executed=%s  agent=%s", action, execution.get("executed"), agent_name)
    log.info("=" * 60)

    return {
        "decision": decision,
        "agent": agent_name,
        "agent_os": target_os,
        "execution": execution,
        "deduplicated": False,
    }


@app.post("/analyze")
async def analyze_only(alert: WazuhAlert):
    log.info("=" * 60)
    log.info("[DRY RUN] Analyzing alert — no SSH execution")
    log.info("  Agent: %s  Rule: %s (level %d)", alert.agent.name, alert.rule.description, alert.rule.level)

    agent = AGENTS.get(alert.agent.name)
    target_os = agent.get("os", "ubuntu") if agent else "ubuntu"

    log.info("[DRY RUN] Sending to Ollama (%s)...", OLLAMA_MODEL)
    try:
        result = await ask_ollama(alert.model_dump(), target_os)
    except Exception as e:
        log.error("[DRY RUN] Ollama failed: %s", e)
        return {"action": "IGNORE", "summary": f"LLM error: {e}", "script": ""}

    log.info("[DRY RUN] AI says: %s — %s", result.get("action"), result.get("summary"))
    log.info("=" * 60)
    return result


@app.get("/audit")
async def audit():
    return list(reversed(AUDIT))
