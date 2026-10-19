import json
import logging
import os
import re
from urllib.error import HTTPError, URLError
from urllib.request import Request, urlopen

logger = logging.getLogger(__name__)

GITHUB_API = "https://api.github.com"
DEFAULT_REPOSITORY = "tejass27is/DomainSecurityScanner"
DEFAULT_REF = "main"
SUPPORTED_TOOLS = {"semgrep", "prowler"}


class ToolUpdateError(RuntimeError):
    pass


def dispatch_tool_update(tool: str, version: str) -> dict:
    if tool not in SUPPORTED_TOOLS:
        raise ToolUpdateError("The requested scanner tool is not supported.")
    if not re.fullmatch(r"[A-Za-z0-9.!+_-]+", version):
        raise ToolUpdateError("The release version contains unsupported characters.")

    token = os.getenv("TOOL_UPDATE_GITHUB_TOKEN", "").strip()
    if not token:
        raise ToolUpdateError(
            "Automatic updates are not configured. Set TOOL_UPDATE_GITHUB_TOKEN on the backend."
        )

    repository = os.getenv("TOOL_UPDATE_REPOSITORY", DEFAULT_REPOSITORY).strip()
    if not re.fullmatch(r"[A-Za-z0-9_.-]+/[A-Za-z0-9_.-]+", repository):
        raise ToolUpdateError("TOOL_UPDATE_REPOSITORY must be in owner/repository format.")
    ref = os.getenv("TOOL_UPDATE_REF", DEFAULT_REF).strip()
    if not re.fullmatch(r"[A-Za-z0-9._/-]+", ref) or ".." in ref:
        raise ToolUpdateError("TOOL_UPDATE_REF is invalid.")

    url = f"{GITHUB_API}/repos/{repository}/actions/workflows/backend.yml/dispatches"
    payload = json.dumps(
        {"ref": ref, "inputs": {"tool": tool, "version": version}}
    ).encode("utf-8")
    request = Request(
        url,
        data=payload,
        method="POST",
        headers={
            "Accept": "application/vnd.github+json",
            "Authorization": f"Bearer {token}",
            "Content-Type": "application/json",
            "User-Agent": "DomainSecurityScanner",
            "X-GitHub-Api-Version": "2022-11-28",
        },
    )
    try:
        with urlopen(request, timeout=15) as response:
            if response.status != 204:
                raise ToolUpdateError(
                    f"GitHub accepted an unexpected response ({response.status}) when starting the update."
                )
    except HTTPError as exc:
        logger.warning(
            "GitHub rejected the %s update dispatch with HTTP %s", tool, exc.code
        )
        if exc.code == 401 or exc.code == 403:
            message = "GitHub rejected the update token. Check that it has Actions write permission for the configured repository."
        elif exc.code == 404:
            message = "GitHub could not find the configured repository or backend deployment workflow."
        else:
            message = f"GitHub could not start the update (HTTP {exc.code})."
        raise ToolUpdateError(message) from exc
    except (URLError, TimeoutError, OSError) as exc:
        logger.warning("Could not dispatch the %s update workflow: %s", tool, exc)
        raise ToolUpdateError(
            "Could not contact GitHub to start the update. Please try again."
        ) from exc

    return {
        "tool": tool,
        "requested_version": version,
        "status": "queued",
        "workflow_url": f"https://github.com/{repository}/actions/workflows/backend.yml",
    }
