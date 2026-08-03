"""Task dispatcher for cap.delegate task envelopes.

Processes queued task envelopes by dispatching them to the appropriate
model backend via the ASG MCP gateway:

- qwen-worker / qwen-director -> asgcode-build gateway backend
- glm                         -> bolde-exec gateway backend
- opus                        -> codex-exec gateway backend

The dispatcher constructs a canonical request, sends it to the gateway,
and updates the task status with the result.
"""

from __future__ import annotations

import json
import os
import urllib.request
from typing import Any
from urllib.error import URLError

from .model_router import route_model
from .utils import utc_now

# Gateway URL (the ASG MCP gateway running on the tailnet)
GATEWAY_URL = os.environ.get("CAPMESH_GATEWAY_URL", "http://127.0.0.1:17777/mcp")

# Gateway backend -> MCP tool name mapping
BACKEND_TOOLS: dict[str, str] = {
    "asgcode-build": "asgcode_workflow_go",
    "bolde-exec": "codex_exec",
    "codex-exec": "codex_exec",
}

# Timeout for gateway dispatch (seconds)
DISPATCH_TIMEOUT = float(os.environ.get("CAPMESH_DISPATCH_TIMEOUT", "120"))


def dispatch_task(
    envelope: dict[str, Any],
    *,
    routing: dict[str, Any] | None = None,
    gateway_url: str | None = None,
) -> dict[str, Any]:
    """Dispatch a task envelope to the appropriate model backend.

    Args:
        envelope: The task envelope dict (from cap.delegate)
        routing: Optional model routing dict (from model_router.route_model).
                 If None, routing is computed from the envelope.
        gateway_url: Optional gateway URL override.

    Returns:
        Dict with dispatch status, backend used, and result/error.
    """
    task = str(envelope.get("task") or "")
    agent_uri = str(envelope.get("agentUri") or "")
    task_id = str(envelope.get("taskId") or "")

    # Determine routing if not provided
    if routing is None:
        # Try to get routing from the envelope first
        routing = envelope.get("modelRouting")
        if routing is None:
            routing = route_model(
                risk_tier="medium",
                task=task,
            )

    backend = str(routing.get("backend") or "asgcode-build")
    model_tier = str(routing.get("modelTier") or "qwen-worker")
    gateway_tool = BACKEND_TOOLS.get(backend, "asgcode_workflow_go")

    url = gateway_url or GATEWAY_URL

    # Build the gateway request
    # For asgcode-build: use asgcode_workflow_go with --evidence
    # For bolde-exec: use codex_exec
    if backend == "asgcode-build":
        params = {
            "objective": task,
            "evidence": True,
            "synthesize": True,
        }
    elif backend == "bolde-exec":
        params = {
            "prompt": f"Task: {task}\nAgent: {agent_uri}\nTask ID: {task_id}",
        }
    else:
        params = {
            "prompt": task,
        }

    request_body = {
        "jsonrpc": "2.0",
        "id": f"dispatch-{task_id}",
        "method": "tools/call",
        "params": {
            "name": gateway_tool,
            "arguments": params,
        },
    }

    try:
        req = urllib.request.Request(
            url,
            data=json.dumps(request_body).encode("utf-8"),
            headers={"Content-Type": "application/json"},
            method="POST",
        )
        with urllib.request.urlopen(req, timeout=DISPATCH_TIMEOUT) as response:
            response_data = json.loads(response.read().decode("utf-8"))

        if "error" in response_data:
            return {
                "status": "failed",
                "backend": backend,
                "modelTier": model_tier,
                "error": str(response_data["error"]),
                "taskId": task_id,
            }

        result = response_data.get("result", {})
        return {
            "status": "completed",
            "backend": backend,
            "modelTier": model_tier,
            "result": result,
            "taskId": task_id,
            "dispatchedAt": utc_now(),
        }

    except URLError as exc:
        return {
            "status": "failed",
            "backend": backend,
            "modelTier": model_tier,
            "error": f"Gateway unreachable: {exc}",
            "taskId": task_id,
        }
    except Exception as exc:  # noqa: BLE001
        return {
            "status": "failed",
            "backend": backend,
            "modelTier": model_tier,
            "error": str(exc),
            "taskId": task_id,
        }


def dispatch_queued_task(
    con,
    task_id: str,
    *,
    tenant_id: str = "asg",
    gateway_url: str | None = None,
) -> dict[str, Any]:
    """Dispatch a queued task by ID from the task_envelopes table.

    This combines task_runner.process_task with task_dispatcher.dispatch_task:
    1. Loads the task envelope from the DB
    2. Dispatches it to the appropriate backend
    3. Updates the task status with the result
    """
    from .task_runner import process_task, task_status

    # Get the task status first
    status_info = task_status(con, task_id, tenant_id=tenant_id)
    if status_info["status"] not in ("queued", "failed"):
        return {
            "status": "error",
            "error": f"Task is not in a processable state: {status_info['status']}",
            "taskId": task_id,
        }

    envelope = status_info.get("taskEnvelope", {})

    # Dispatch the task
    result = dispatch_task(envelope, gateway_url=gateway_url)

    # Update the task status via process_task with a handler that returns the dispatch result
    def _handler(_env):
        return result

    process_task(con, task_id, _handler, tenant_id=tenant_id, commit=True)
    return result


def list_dispatch_backends() -> list[dict[str, Any]]:
    """List available dispatch backends and their configuration."""
    return [
        {
            "name": "qwen-worker",
            "backend": "asgcode-build",
            "tool": "asgcode_workflow_go",
            "description": "Free local Qwen 3.6 9B Worker (mechanical/atomic/parallel)",
            "cost": "free",
        },
        {
            "name": "qwen-director",
            "backend": "asgcode-build",
            "tool": "asgcode_workflow_go",
            "description": "Free local Qwen 3.6 35B Director (reasoning/synthesis/verify)",
            "cost": "free",
        },
        {
            "name": "glm",
            "backend": "bolde-exec",
            "tool": "codex_exec",
            "description": "Free local GLM-5.2 on B200 (frontier reasoning, 300K context)",
            "cost": "free",
        },
        {
            "name": "opus",
            "backend": "codex-exec",
            "tool": "codex_exec",
            "description": "Cloud GPT-5.6 (critical/irreversible/security artifacts)",
            "cost": "paid",
        },
    ]
