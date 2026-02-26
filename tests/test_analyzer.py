import json
from unittest.mock import AsyncMock, MagicMock, patch

import pytest
from fastapi.testclient import TestClient

from app.llm import ask_ollama
from app.executor import run_ssh


AGENTS = {
    "ubuntu-host": {"host": "10.0.0.1", "port": 22, "username": "admin", "password": "x", "os": "ubuntu"},
    "win-host": {"host": "10.0.0.2", "port": 22, "username": "Admin", "password": "x", "os": "windows"},
}


def _ollama_response(action, script="echo ok", severity="high"):
    return json.dumps({
        "action": action,
        "severity": severity,
        "summary": "test",
        "reason": "test",
        "script": script,
    })


# ── LLM tests ──────────────────────────────────────────────────────────

class TestLLM:
    @pytest.mark.asyncio
    async def test_returns_parsed_json(self):
        fake = _ollama_response("BLOCK_IP", "iptables -A INPUT -s 1.2.3.4 -j DROP")
        with patch("app.llm.httpx.AsyncClient") as mock_cls:
            mock_client = AsyncMock()
            mock_resp = MagicMock()
            mock_resp.json.return_value = {"message": {"content": fake}}
            mock_resp.raise_for_status = MagicMock()
            mock_client.post.return_value = mock_resp
            mock_client.__aenter__ = AsyncMock(return_value=mock_client)
            mock_client.__aexit__ = AsyncMock(return_value=False)
            mock_cls.return_value = mock_client

            result = await ask_ollama({"rule": {"level": 10}}, "ubuntu")

        assert result["action"] == "BLOCK_IP"
        assert "iptables" in result["script"]


# ── Executor tests ──────────────────────────────────────────────────────

class TestExecutor:
    @pytest.mark.asyncio
    async def test_ssh_runs_script(self):
        mock_result = MagicMock(stdout="done\n", stderr="", exit_status=0)
        mock_conn = AsyncMock()
        mock_conn.run = AsyncMock(return_value=mock_result)
        mock_conn.__aenter__ = AsyncMock(return_value=mock_conn)
        mock_conn.__aexit__ = AsyncMock(return_value=False)

        with patch("app.executor.asyncssh.connect", new_callable=AsyncMock, return_value=mock_conn):
            result = await run_ssh("10.0.0.1", 22, "admin", "echo hello", password="x")

        assert result["success"] is True
        assert result["output"] == "done"

    @pytest.mark.asyncio
    async def test_ssh_failure(self):
        with patch("app.executor.asyncssh.connect", new_callable=AsyncMock, side_effect=OSError("refused")):
            result = await run_ssh("10.0.0.1", 22, "admin", "echo hello", password="x")

        assert result["success"] is False
        assert "SSH connection failed" in result["error"]

    @pytest.mark.asyncio
    async def test_windows_wraps_powershell(self):
        mock_result = MagicMock(stdout="ok\n", stderr="", exit_status=0)
        mock_conn = AsyncMock()
        mock_conn.run = AsyncMock(return_value=mock_result)
        mock_conn.__aenter__ = AsyncMock(return_value=mock_conn)
        mock_conn.__aexit__ = AsyncMock(return_value=False)

        with patch("app.executor.asyncssh.connect", new_callable=AsyncMock, return_value=mock_conn):
            await run_ssh("10.0.0.2", 22, "Admin", "Get-Process", password="x", target_os="windows")

        cmd = mock_conn.run.call_args[0][0]
        assert "powershell" in cmd


# ── API tests ───────────────────────────────────────────────────────────

class TestAPI:
    def _client(self):
        import app.main as m
        m.AGENTS = AGENTS
        return TestClient(m.app)

    def test_health(self):
        c = self._client()
        r = c.get("/health")
        assert r.status_code == 200
        assert r.json()["status"] == "ok"

    def test_webhook_ignore(self):
        c = self._client()
        llm = _ollama_response("IGNORE", "")
        with patch("app.main.ask_ollama", new_callable=AsyncMock, return_value=json.loads(llm)):
            r = c.post("/webhook", json={
                "rule": {"id": "1", "level": 2, "description": "heartbeat"},
                "agent": {"name": "ubuntu-host"},
                "full_log": "agent heartbeat",
            })
        body = r.json()
        assert body["decision"]["action"] == "IGNORE"
        assert body["execution"]["executed"] is False

    def test_webhook_executes(self):
        c = self._client()
        llm = json.loads(_ollama_response("BLOCK_IP", "iptables -A INPUT -s 5.5.5.5 -j DROP"))
        ssh_result = {"success": True, "output": "rule added", "error": ""}

        with (
            patch("app.main.ask_ollama", new_callable=AsyncMock, return_value=llm),
            patch("app.main.run_ssh", new_callable=AsyncMock, return_value=ssh_result),
        ):
            r = c.post("/webhook", json={
                "rule": {"id": "5710", "level": 10, "description": "brute force"},
                "agent": {"name": "ubuntu-host"},
                "data": {"srcip": "5.5.5.5"},
                "full_log": "Failed password from 5.5.5.5",
            })
        body = r.json()
        assert body["decision"]["action"] == "BLOCK_IP"
        assert body["execution"]["executed"] is True
        assert body["execution"]["output"] == "rule added"

    def test_webhook_unknown_agent(self):
        c = self._client()
        llm = json.loads(_ollama_response("BLOCK_IP", "iptables ..."))

        with patch("app.main.ask_ollama", new_callable=AsyncMock, return_value=llm):
            r = c.post("/webhook", json={
                "rule": {"id": "5710", "level": 10, "description": "scan"},
                "agent": {"name": "unknown-box"},
                "full_log": "nmap scan",
            })
        body = r.json()
        assert body["execution"]["executed"] is False
        assert "not in inventory" in body["execution"]["error"]

    def test_analyze_dry_run(self):
        c = self._client()
        llm = json.loads(_ollama_response("KILL_PROCESS", "kill -9 1234"))

        with patch("app.main.ask_ollama", new_callable=AsyncMock, return_value=llm):
            r = c.post("/analyze", json={
                "rule": {"id": "999", "level": 12, "description": "miner"},
                "agent": {"name": "ubuntu-host"},
                "full_log": "xmrig running",
            })
        assert r.json()["action"] == "KILL_PROCESS"
        assert "kill" in r.json()["script"]

    def test_audit(self):
        c = self._client()
        r = c.get("/audit")
        assert r.status_code == 200
