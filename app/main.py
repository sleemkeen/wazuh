import asyncio
import json
import logging
from datetime import datetime, timezone

import redis.asyncio as redis
from fastapi import FastAPI
from fastapi.middleware.cors import CORSMiddleware
from pydantic import BaseModel, Field

from .config import (
    DEDUP_WINDOW,
    MIN_LEVEL,
    OLLAMA_BASE_URL,
    OLLAMA_MODEL,
    REDIS_URL,
    load_agents,
)
from .executor import run_ssh
from .llm import ask_ollama

logging.basicConfig(level=logging.INFO, format="%(asctime)s  %(levelname)-8s  %(message)s")
log = logging.getLogger("soc")

app = FastAPI(title="SOC Remediation", version="3.0.0")
app.add_middleware(CORSMiddleware, allow_origins=["*"], allow_methods=["*"], allow_headers=["*"])

AGENTS: dict = {}
AUDIT: list[dict] = []

rdb: redis.Redis | None = None

QUEUE_KEY = "soc:queue"
DEDUP_PREFIX = "soc:dedup:"
PROCESSING_LOCK = asyncio.Lock()


def _dedup_key(agent_name: str, rule_id: str, data: dict) -> str:
    srcip = data.get("srcip", data.get("src_ip", ""))
    user = data.get("dstuser", data.get("user", ""))
    return f"{DEDUP_PREFIX}{agent_name}|{rule_id}|{srcip}|{user}"


@app.on_event("startup")
async def startup():
    global AGENTS, rdb
    AGENTS = load_agents()
    rdb = redis.from_url(REDIS_URL, decode_responses=True)
    await rdb.ping()
    log.info("Redis connected: %s", REDIS_URL)
    log.info("Loaded %d agent(s): %s", len(AGENTS), list(AGENTS.keys()))
    log.info("Ollama: %s  model: %s", OLLAMA_BASE_URL, OLLAMA_MODEL)
    log.info("Min level: %d  Dedup window: %ds", MIN_LEVEL, DEDUP_WINDOW)

    asyncio.create_task(_worker())
    log.info("Queue worker started — processing 1 alert at a time")


@app.on_event("shutdown")
async def shutdown():
    if rdb:
        await rdb.aclose()


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
    queue_len = await rdb.llen(QUEUE_KEY) if rdb else 0
    return {
        "status": "ok",
        "ollama": OLLAMA_BASE_URL,
        "model": OLLAMA_MODEL,
        "agents": list(AGENTS.keys()),
        "redis": REDIS_URL,
        "queue_length": queue_len,
        "min_level": MIN_LEVEL,
        "dedup_window_seconds": DEDUP_WINDOW,
    }


@app.post("/webhook")
async def webhook(alert: WazuhAlert):
    agent_name = alert.agent.name

    if alert.rule.level < MIN_LEVEL:
        log.info("[FILTERED] Level %d < %d — %s. IGNORE.", alert.rule.level, MIN_LEVEL, alert.rule.description)
        return {
            "status": "filtered",
            "reason": f"Level {alert.rule.level} below threshold ({MIN_LEVEL}).",
        }

    key = _dedup_key(agent_name, alert.rule.id, alert.data)
    if rdb and await rdb.exists(key):
        ttl = await rdb.ttl(key)
        log.info("[DEDUP] Already handled. Cooldown %ds remaining. Key: %s", ttl, key)
        return {
            "status": "deduplicated",
            "reason": f"Already remediated. Cooldown {ttl}s remaining.",
        }

    payload = alert.model_dump_json()
    await rdb.rpush(QUEUE_KEY, payload)
    queue_len = await rdb.llen(QUEUE_KEY)
    log.info("[QUEUED] Rule [%s] %s → position %d in queue", alert.rule.id, alert.rule.description, queue_len)

    return {
        "status": "queued",
        "queue_position": queue_len,
        "agent": agent_name,
        "rule": alert.rule.description,
    }


async def _process_alert(raw: str):
    alert = WazuhAlert.model_validate_json(raw)
    agent_name = alert.agent.name
    agent = AGENTS.get(agent_name)
    target_os = agent.get("os", "ubuntu") if agent else "ubuntu"

    log.info("=" * 60)
    log.info("[STEP 1] PROCESSING ALERT FROM QUEUE")
    log.info("  Agent: '%s'  OS: %s", agent_name, target_os)
    if agent:
        log.info("  Agent FOUND → %s@%s", agent["username"], agent["host"])
    else:
        log.warning("  Agent '%s' NOT FOUND. Available: %s", agent_name, list(AGENTS.keys()))
    log.info("  Rule: [%s] %s (level %d)", alert.rule.id, alert.rule.description, alert.rule.level)
    log.info("  Log: %s", alert.full_log[:200])

    key = _dedup_key(agent_name, alert.rule.id, alert.data)
    if rdb and await rdb.exists(key):
        log.info("[DEDUP] Already handled while queued. Skipping.")
        log.info("=" * 60)
        return

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

    executed = False
    output = ""
    error = ""

    if action != "IGNORE" and script and agent:
        log.info("[STEP 4] EXECUTING via SSH on %s (%s)...", agent_name, agent["host"])
        result = await run_ssh(
            host=agent["host"],
            port=agent.get("port", 22),
            username=agent["username"],
            script=script,
            password=agent.get("password"),
            key_file=agent.get("key_file"),
            target_os=target_os,
        )
        executed = True
        output = result.get("output", "")
        error = result.get("error", "")

        if result["success"]:
            log.info("[STEP 5] EXECUTION SUCCESS")
            log.info("  Output: %s", output[:300])
        else:
            log.error("[STEP 5] EXECUTION FAILED")
            log.error("  Error: %s", error[:300])

        if rdb:
            await rdb.setex(key, DEDUP_WINDOW, "1")
            log.info("[DEDUP] Cooldown set: %ds for %s", DEDUP_WINDOW, key)
    elif action != "IGNORE" and not agent:
        log.warning("[STEP 4] SKIPPED — agent '%s' not in inventory", agent_name)
    else:
        log.info("[STEP 4] SKIPPED — action is IGNORE")

    AUDIT.append({
        "timestamp": datetime.now(timezone.utc).isoformat(),
        "agent": agent_name,
        "rule": alert.rule.description,
        "level": alert.rule.level,
        "action": action,
        "executed": executed,
        "output": output[:200],
        "error": error[:200],
    })

    log.info("[DONE] action=%s  executed=%s  agent=%s", action, executed, agent_name)
    log.info("=" * 60)


async def _worker():
    log.info("[WORKER] Waiting for alerts...")
    while True:
        try:
            item = await rdb.blpop(QUEUE_KEY, timeout=1)
            if item:
                _, raw = item
                queue_len = await rdb.llen(QUEUE_KEY)
                log.info("[WORKER] Processing alert (%d remaining in queue)", queue_len)
                await _process_alert(raw)
        except Exception as e:
            log.error("[WORKER] Error: %s", e)
            await asyncio.sleep(2)


@app.post("/analyze")
async def analyze_only(alert: WazuhAlert):
    log.info("[DRY RUN] Rule: %s (level %d)", alert.rule.description, alert.rule.level)
    agent = AGENTS.get(alert.agent.name)
    target_os = agent.get("os", "ubuntu") if agent else "ubuntu"
    try:
        return await ask_ollama(alert.model_dump(), target_os)
    except Exception as e:
        return {"action": "IGNORE", "summary": f"LLM error: {e}", "script": ""}


@app.get("/audit")
async def audit():
    return list(reversed(AUDIT))


@app.get("/queue")
async def queue_status():
    queue_len = await rdb.llen(QUEUE_KEY) if rdb else 0
    return {"queue_length": queue_len}
