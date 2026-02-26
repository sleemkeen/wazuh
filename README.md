# SOC Remediation Service

AI-powered Wazuh alert analysis with **automated SSH remediation** on Ubuntu and Windows targets.

## Architecture

```
Wazuh  ──webhook──▶  FastAPI  ──▶  Ollama LLM
                                       │
                                  AI Decision
                                  (action + target)
                                       │
                              ┌────────┴────────┐
                              │  Action Registry │
                              │  Ubuntu (bash)   │
                              │  Windows (PS)    │
                              └────────┬────────┘
                                       │
                              ┌────────┴────────┐
                              │  SSH Executor    │
                              │  → run command   │
                              │  → verify result │
                              └────────┬────────┘
                                       │
                               Execution Result
```

## How it works

1. **Wazuh sends an alert** to `POST /webhook`
2. The alert is forwarded to **Ollama** — the LLM decides the action, severity, target, and reason
3. The action is **validated** against the allowlist (invalid → IGNORE)
4. Platform-specific commands are rendered from the **action registry** (Ubuntu bash or Windows PowerShell)
5. The service **SSHs into the target agent** and executes the remediation command + verification
6. The full **execution result** is returned

## Quick Start

### Docker Compose

```bash
docker compose up --build -d
docker exec soc-ollama ollama pull llama3
```

### Local

```bash
ollama serve &
ollama pull llama3

pip install -r requirements.txt
uvicorn app.main:app --reload
```

## Configuration

### Environment variables

| Variable          | Default                  | Description                    |
|-------------------|--------------------------|--------------------------------|
| `OLLAMA_BASE_URL` | `http://localhost:11434` | Ollama API endpoint            |
| `OLLAMA_MODEL`    | `llama3`                 | Model for analysis             |
| `OLLAMA_TIMEOUT`  | `120`                    | Request timeout (seconds)      |
| `AGENTS_FILE`     | `agents.json`            | Path to agent inventory        |

### Agent inventory (`agents.json`)

Maps Wazuh agent names to SSH connection details:

```json
{
  "web-server-01": {
    "host": "192.168.1.10",
    "port": 22,
    "username": "admin",
    "password": "changeme",
    "os": "ubuntu"
  },
  "win-server-01": {
    "host": "192.168.1.20",
    "port": 22,
    "username": "Administrator",
    "password": "changeme",
    "os": "windows"
  }
}
```

Supported `os` values: `ubuntu`, `windows`

SSH keys: set `key_file` instead of `password` and mount your key into the container.

## API Endpoints

| Method | Path             | Description                               |
|--------|------------------|-------------------------------------------|
| GET    | `/health`        | Health check + config                     |
| GET    | `/agents`        | List registered agents (passwords hidden) |
| POST   | `/webhook`       | Full pipeline: AI analyze → SSH execute   |
| POST   | `/analyze-only`  | AI analysis only — dry run, no SSH        |
| POST   | `/batch`         | Process multiple alerts                   |
| GET    | `/audit`         | In-memory audit trail                     |

Interactive docs: `http://localhost:8000/docs`

## Action Registry

### Ubuntu (bash)

| Action            | Command                                    |
|-------------------|--------------------------------------------|
| `BLOCK_IP`        | `iptables -A INPUT -s <IP> -j DROP`        |
| `DISABLE_ACCOUNT` | `usermod -L <USER>`                        |
| `KILL_PROCESS`    | `kill -9 <PID>`                            |
| `REVERT_CONFIG`   | `cp /backup/secure_config /etc/target`     |

### Windows (PowerShell)

| Action            | Command                                                        |
|-------------------|----------------------------------------------------------------|
| `BLOCK_IP`        | `New-NetFirewallRule -DisplayName "SOC-Block-<IP>" ...`        |
| `DISABLE_ACCOUNT` | `Disable-LocalUser -Name '<USER>'`                             |
| `KILL_PROCESS`    | `Stop-Process -Id <PID> -Force`                                |
| `REVERT_CONFIG`   | `Copy-Item C:\backup\secure_config C:\target_config -Force`    |

## Example

```bash
curl -X POST http://localhost:8000/webhook \
  -H "Content-Type: application/json" \
  -d '{
    "timestamp": "2026-02-26T10:15:32Z",
    "rule": {"id": "5710", "level": 10, "description": "Multiple authentication failures"},
    "agent": {"name": "web-server-01"},
    "data": {"srcip": "203.0.113.50"},
    "full_log": "sshd: Failed password for root from 203.0.113.50 port 42218 ssh2"
  }'
```

Response:

```json
{
  "decision": {
    "summary": "Brute-force SSH attack from 203.0.113.50",
    "severity": "high",
    "recommended_action": "BLOCK_IP",
    "target": { "ip": "203.0.113.50", "user": "", "process": "" },
    "reason": "Repeated failed SSH login attempts from single source IP.",
    "command": "iptables -A INPUT -s 203.0.113.50 -j DROP",
    "verification": "iptables -L INPUT -n | grep 203.0.113.50",
    "rollback": "iptables -D INPUT -s 203.0.113.50 -j DROP"
  },
  "executed": true,
  "agent_name": "web-server-01",
  "agent_os": "ubuntu",
  "command_output": "",
  "verification_output": "DROP  all  --  203.0.113.50  0.0.0.0/0",
  "error": ""
}
```

## Tests

```bash
pytest tests/ -v
```

All Ollama and SSH calls are mocked — no live services needed.
