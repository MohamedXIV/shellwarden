"""ShellWarden execution broker.

This process normalizes a JSON-lines request, applies the bootstrap positive
policy, then delegates argv execution to the pinned mcp-shell-server
ShellExecutor. stdout is reserved for protocol messages.
"""

from __future__ import annotations

import asyncio
import json
import os
import sys
import types
from pathlib import Path
from typing import Any

EXPECTED_CORE_VERSION = "1.1.12"
BOOTSTRAP_ALLOWED_COMMANDS = {"git"}


def _install_windows_pwd_compat() -> None:
    """Bridge the upstream import-time Unix-only pwd dependency on Windows."""

    if os.name != "nt":
        return

    if "pwd" not in sys.modules:
        module = types.ModuleType("pwd")

        class _Passwd:
            pw_shell = os.environ.get("COMSPEC", "cmd.exe")

        def getpwuid(_uid: int) -> _Passwd:
            return _Passwd()

        module.getpwuid = getpwuid
        sys.modules["pwd"] = module

    if not hasattr(os, "getuid"):
        os.getuid = lambda: 0


_install_windows_pwd_compat()

from mcp_shell_server import __version__ as core_version
from mcp_shell_server.shell_executor import ShellExecutor


def _emit(payload: dict[str, Any]) -> None:
    sys.stdout.write(json.dumps(payload, separators=(",", ":")) + "\n")
    sys.stdout.flush()


def _error(request_id: str | None, message: str) -> dict[str, Any]:
    return {
        "type": "response",
        "id": request_id,
        "ok": False,
        "error": message,
        "coreVersion": core_version,
    }


def _normalize_request(payload: Any) -> tuple[str | None, str, dict[str, Any]]:
    if not isinstance(payload, dict):
        raise ValueError("request must be a JSON object")

    request_id = payload.get("id")
    if request_id is not None and not isinstance(request_id, str):
        raise ValueError("id must be a string when provided")

    request_type = payload.get("type")
    if request_type not in {"health", "execute"}:
        raise ValueError("type must be 'health' or 'execute'")

    return request_id, request_type, payload


async def _execute(
    executor: ShellExecutor,
    request_id: str | None,
    payload: dict[str, Any],
) -> dict[str, Any]:
    command = payload.get("command")
    directory = payload.get("directory")
    timeout = payload.get("timeout")

    if not isinstance(command, list) or not command or not all(
        isinstance(part, str) and part for part in command
    ):
        return _error(request_id, "command must be a non-empty string array")

    if command[0] not in BOOTSTRAP_ALLOWED_COMMANDS:
        return _error(
            request_id,
            f"bootstrap policy does not allow executable: {command[0]}",
        )

    if not isinstance(directory, str) or not directory:
        return _error(request_id, "directory must be a non-empty string")

    canonical_directory = str(Path(directory).resolve())

    if timeout is not None and (
        isinstance(timeout, bool) or not isinstance(timeout, int) or timeout <= 0
    ):
        return _error(request_id, "timeout must be a positive integer")

    if "envs" in payload:
        return _error(
            request_id,
            "per-request environment overrides are not exposed by the bootstrap broker",
        )

    result = await executor.execute(
        command=command,
        directory=canonical_directory,
        timeout=timeout,
    )

    return {
        "type": "response",
        "id": request_id,
        "ok": result.get("status") == 0,
        "coreVersion": core_version,
        "result": result,
    }


async def _handle(executor: ShellExecutor, payload: Any) -> dict[str, Any]:
    request_id: str | None = None

    try:
        request_id, request_type, normalized = _normalize_request(payload)

        if request_type == "health":
            return {
                "type": "response",
                "id": request_id,
                "ok": True,
                "coreVersion": core_version,
                "allowedCommands": sorted(BOOTSTRAP_ALLOWED_COMMANDS),
            }

        return await _execute(executor, request_id, normalized)
    except Exception as exc:
        return _error(request_id, str(exc))


def main() -> int:
    if core_version != EXPECTED_CORE_VERSION:
        _emit(
            {
                "type": "fatal",
                "ok": False,
                "error": (
                    f"mcp-shell-server version mismatch: expected "
                    f"{EXPECTED_CORE_VERSION}, got {core_version}"
                ),
                "coreVersion": core_version,
            }
        )
        return 2

    os.environ["ALLOW_COMMANDS"] = ",".join(sorted(BOOTSTRAP_ALLOWED_COMMANDS))
    os.environ.pop("ALLOWED_COMMANDS", None)
    os.environ.pop("ALLOW_PATTERNS", None)

    executor = ShellExecutor()

    _emit(
        {
            "type": "ready",
            "ok": True,
            "coreVersion": core_version,
            "allowedCommands": sorted(BOOTSTRAP_ALLOWED_COMMANDS),
        }
    )

    for line in sys.stdin:
        line = line.strip()
        if not line:
            continue

        try:
            payload = json.loads(line)
        except json.JSONDecodeError as exc:
            _emit(_error(None, f"invalid JSON: {exc.msg}"))
            continue

        _emit(asyncio.run(_handle(executor, payload)))

    return 0


if __name__ == "__main__":
    raise SystemExit(main())
