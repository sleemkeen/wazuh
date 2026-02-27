import asyncio
import logging
import time
import uuid
from datetime import datetime, timezone

import redis.asyncio as redis
from fastapi import FastAPI
from fastapi.middleware.cors import CORSMiddleware
from pydantic import BaseModel, Field

from .config import MIN_LEVEL, OLLAMA_BASE_URL, OLLAMA_MODEL, REDIS_URL, load_agents
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
JOB_PREFIX = "soc:job:"


@app.on_event("startup")
async def startup():
    global AGENTS, rdb
    AGENTS = load_agents()
    rdb = redis.from_url(REDIS_URL, decode_responses=True)
    await rdb.ping()
    log.info("Redis connected: %s", REDIS_URL)
    log.info("Loaded %d agent(s): %s", len(AGENTS), list(AGENTS.keys()))
    log.info("Ollama: %s  model: %s", OLLAMA_BASE_URL, OLLAMA_MODEL)
    log.info("Min level: %d", MIN_LEVEL)

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

    job_id = str(uuid.uuid4())[:8]
    job_data = {
        "job_id": job_id,
        "alert": alert.model_dump(),
        "status": "queued",
        "queued_at": datetime.now(timezone.utc).isoformat(),
    }

    import json
    await rdb.rpush(QUEUE_KEY, json.dumps(job_data))
    await rdb.setex(f"{JOB_PREFIX}{job_id}", 300, json.dumps({"status": "queued", "queued_at": job_data["queued_at"]}))
    queue_len = await rdb.llen(QUEUE_KEY)

    log.info("[QUEUED] job=%s  Rule [%s] %s → position %d", job_id, alert.rule.id, alert.rule.description, queue_len)

    return {
        "status": "queued",
        "job_id": job_id,
        "queue_position": queue_len,
        "agent": agent_name,
        "rule": alert.rule.description,
    }


@app.get("/job/{job_id}")
async def get_job(job_id: str):
    import json
    raw = await rdb.get(f"{JOB_PREFIX}{job_id}")
    if not raw:
        return {"error": f"Job {job_id} not found or expired."}
    return json.loads(raw)


async def _process_alert(raw: str):
    import json
    job_data = json.loads(raw)
    job_id = job_data["job_id"]
    alert = WazuhAlert.model_validate(job_data["alert"])
    agent_name = alert.agent.name
    agent = AGENTS.get(agent_name)
    target_os = agent.get("os", "ubuntu") if agent else "ubuntu"
    start = time.time()

    await rdb.setex(f"{JOB_PREFIX}{job_id}", 300, json.dumps({"status": "processing", "started_at": datetime.now(timezone.utc).isoformat()}))

    log.info("=" * 60)
    log.info("[STEP 1] job=%s  PROCESSING ALERT", job_id)
    log.info("  Agent: '%s'  OS: %s", agent_name, target_os)
    if agent:
        log.info("  Agent FOUND → %s@%s", agent["username"], agent["host"])
    else:
        log.warning("  Agent '%s' NOT FOUND. Available: %s", agent_name, list(AGENTS.keys()))
    log.info("  Rule: [%s] %s (level %d)", alert.rule.id, alert.rule.description, alert.rule.level)
    log.info("  Log: %s", alert.full_log[:200])

    log.info("[STEP 2] job=%s  SENDING TO OLLAMA (%s)...", job_id, OLLAMA_MODEL)
    try:
        decision = await ask_ollama(alert.model_dump(), target_os)
    except Exception as e:
        log.error("[STEP 2] job=%s  OLLAMA FAILED: %s", job_id, e)
        decision = {
            "action": "IGNORE",
            "severity": "low",
            "summary": f"LLM error: {e}",
            "reason": "Ollama unavailable, defaulting to IGNORE.",
            "script": "",
        }

    action = decision.get("action", "IGNORE")
    script = decision.get("script", "")

    log.info("[STEP 3] job=%s  AI DECISION", job_id)
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
        log.info("[STEP 4] job=%s  EXECUTING via SSH on %s (%s)...", job_id, agent_name, agent["host"])
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
            log.info("[STEP 5] job=%s  EXECUTION SUCCESS", job_id)
            log.info("  Output: %s", output[:300])
        else:
            log.error("[STEP 5] job=%s  EXECUTION FAILED", job_id)
            log.error("  Error: %s", error[:300])
    elif action != "IGNORE" and not agent:
        log.warning("[STEP 4] job=%s  SKIPPED — agent '%s' not in inventory", job_id, agent_name)
    else:
        log.info("[STEP 4] job=%s  SKIPPED — action is IGNORE", job_id)

    elapsed = round(time.time() - start, 2)

    job_result = {
        "status": "completed",
        "job_id": job_id,
        "agent": agent_name,
        "rule": alert.rule.description,
        "level": alert.rule.level,
        "action": action,
        "executed": executed,
        "output": output[:500],
        "error": error[:500],
        "elapsed_seconds": elapsed,
        "completed_at": datetime.now(timezone.utc).isoformat(),
    }
    await rdb.setex(f"{JOB_PREFIX}{job_id}", 300, json.dumps(job_result))

    AUDIT.append(job_result)
    if len(AUDIT) > 200:
        AUDIT[:] = AUDIT[-200:]

    log.info("[DONE] job=%s  action=%s  executed=%s  agent=%s  took=%.2fs", job_id, action, executed, agent_name, elapsed)
    log.info("=" * 60)


async def _worker():
    log.info("[WORKER] Waiting for alerts...")
    while True:
        try:
            item = await rdb.blpop(QUEUE_KEY, timeout=1)
            if item:
                _, raw = item
                queue_len = await rdb.llen(QUEUE_KEY)
                log.info("[WORKER] Picked up job (%d remaining in queue)", queue_len)
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
