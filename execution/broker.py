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
from contextvars import ContextVar
from pathlib import Path
from typing import Any, Callable

EXPECTED_CORE_VERSION = "1.1.12"
BOOTSTRAP_ALLOWED_COMMANDS = {"git"}
STREAM_CHUNK_BYTES = 8192
_CURRENT_REQUEST_ID: ContextVar[str | None] = ContextVar(
    "shellwarden_execution_id", default=None
)


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
from mcp_shell_server.process_manager import OutputLimitExceeded, ProcessManager
from mcp_shell_server.shell_executor import ShellExecutor


def _emit(payload: dict[str, Any]) -> None:
    sys.stdout.write(json.dumps(payload, separators=(",", ":")) + "\n")
    sys.stdout.flush()


def _emit_event(request_id: str | None, event: str, **fields: Any) -> None:
    _emit({"type": "event", "id": request_id, "event": event, **fields})


class StreamingProcessManager(ProcessManager):
    """Mirror bounded stdout/stderr chunks while preserving upstream execution."""

    def __init__(self, sink: Callable[[dict[str, Any]], None]) -> None:
        self._stream_sink = sink
        super().__init__()

    async def _read_stream_limited(
        self,
        stream: Any,
        stream_name: str,
        limit: int,
    ) -> bytes:
        if stream is None:
            return b""

        data = bytearray()
        while True:
            remaining = max(1, limit + 1 - len(data))
            chunk = await stream.read(min(STREAM_CHUNK_BYTES, remaining))
            if not chunk:
                return bytes(data)

            data.extend(chunk)
            request_id = _CURRENT_REQUEST_ID.get()
            if request_id is not None:
                self._stream_sink(
                    {
                        "type": "event",
                        "id": request_id,
                        "event": "output",
                        "stream": stream_name,
                        "chunk": chunk.decode(errors="replace"),
                    }
                )

            if len(data) > limit:
                partial = bytes(data[:limit])
                if stream_name == "stdout":
                    raise OutputLimitExceeded(stream_name, limit, stdout=partial)
                raise OutputLimitExceeded(stream_name, limit, stderr=partial)


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
        message = "command must be a non-empty string array"
        _emit_event(request_id, "failed", reason=message)
        return _error(request_id, message)

    if command[0] not in BOOTSTRAP_ALLOWED_COMMANDS:
        message = f"bootstrap policy does not allow executable: {command[0]}"
        _emit_event(request_id, "denied", reason=message)
        return _error(request_id, message)

    if not isinstance(directory, str) or not directory:
        message = "directory must be a non-empty string"
        _emit_event(request_id, "failed", reason=message)
        return _error(request_id, message)

    canonical_directory = str(Path(directory).resolve())

    if timeout is not None and (
        isinstance(timeout, bool) or not isinstance(timeout, int) or timeout <= 0
    ):
        message = "timeout must be a positive integer"
        _emit_event(request_id, "failed", reason=message)
        return _error(request_id, message)

    if "envs" in payload:
        message = "per-request environment overrides are not exposed by the bootstrap broker"
        _emit_event(request_id, "denied", reason=message)
        return _error(request_id, message)

    _emit_event(
        request_id,
        "running",
        command=command,
        directory=canonical_directory,
    )

    token = _CURRENT_REQUEST_ID.set(request_id)
    try:
        result = await executor.execute(
            command=command,
            directory=canonical_directory,
            timeout=timeout,
        )
    finally:
        _CURRENT_REQUEST_ID.reset(token)

    status = result.get("status")
    error = result.get("error")
    if status == 0:
        terminal_event = "succeeded"
    elif status == -1 and isinstance(error, str) and "timed out" in error.lower():
        terminal_event = "timed_out"
    else:
        terminal_event = "failed"

    _emit_event(
        request_id,
        terminal_event,
        status=status,
        executionTime=result.get("execution_time"),
        reason=error,
    )

    return {
        "type": "response",
        "id": request_id,
        "ok": status == 0,
        "coreVersion": core_version,
        "result": result,
    }


async def _handle(executor: ShellExecutor, payload: Any) -> dict[str, Any]:
    request_id: str | None = None
    request_type: str | None = None

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

        _emit_event(request_id, "requested")
        return await _execute(executor, request_id, normalized)
    except Exception as exc:
        if request_type == "execute":
            _emit_event(request_id, "failed", reason=str(exc))
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

    process_manager = StreamingProcessManager(_emit)
    executor = ShellExecutor(process_manager=process_manager)

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
