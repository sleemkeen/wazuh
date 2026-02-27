import asyncio
import logging

import asyncssh

log = logging.getLogger("soc")


async def run_ssh(host: str, port: int, username: str, script: str,
                  password: str | None = None, key_file: str | None = None,
                  target_os: str = "ubuntu") -> dict:

    connect_args: dict = {
        "host": host,
        "port": port,
        "username": username,
        "known_hosts": None,
    }
    if key_file:
        connect_args["client_keys"] = [key_file]
    if password:
        connect_args["password"] = password

    if target_os == "windows":
        escaped = script.replace('"', '`"')
        command = f'powershell -NoProfile -Command "{escaped}"'
    else:
        command = f'bash -c {repr(script)}'

    log.info("  SSH connecting to %s@%s:%d (%s)...", username, host, port, target_os)

    try:
        conn = await asyncio.wait_for(asyncssh.connect(**connect_args), timeout=15)
    except Exception as e:
        log.error("  SSH connection failed: %s", e)
        return {"success": False, "output": "", "error": f"SSH connection failed: {e}"}

    log.info("  SSH connected. Running command...")

    async with conn:
        try:
            result = await asyncio.wait_for(conn.run(command), timeout=30)
        except Exception as e:
            log.error("  SSH command failed: %s", e)
            return {"success": False, "output": "", "error": f"Execution failed: {e}"}

    stdout = (result.stdout or "").strip()
    stderr = (result.stderr or "").strip()

    log.info("  SSH exit code: %d", result.exit_status)
    if stdout:
        log.info("  SSH stdout: %s", stdout[:300])
    if stderr:
        log.info("  SSH stderr: %s", stderr[:300])

    return {
        "success": result.exit_status == 0,
        "output": stdout,
        "error": stderr if result.exit_status != 0 else "",
    }
