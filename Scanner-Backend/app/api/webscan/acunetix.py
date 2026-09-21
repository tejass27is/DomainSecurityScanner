"""Acunetix Premium (on-prem, v13+) REST client.

Only the *create and start* half of the lifecycle lives here. Once a scan is
running, the Go ``worker-webscan`` polls Acunetix (and pulls the findings) so
the API process never blocks on a scan that can take minutes to hours.

Authentication uses the API key generated in Acunetix →
*Profile → API key*, sent as the ``X-Auth`` header.

The base URL is read from ``ACUNETIX_URL`` (or its older alias
``ACUNETIX_BASE_URL``). Either the bare console address
(``https://acunetix.example.com:3443``) or the API root
(``https://acunetix.example.com:3443/api/v1``) is accepted — see
:func:`resolve_base_url`, which normalizes both to the API root that the paths
below are appended to.
"""

import os
import logging

import httpx

logger = logging.getLogger(__name__)


class AcunetixError(RuntimeError):
    """Raised when Acunetix is misconfigured, unreachable, or answers with an error."""


def _env_bool(name: str, default: bool = False) -> bool:
    raw = os.getenv(name)
    if raw is None or str(raw).strip() == "":
        return default
    return str(raw).strip().lower() in {"1", "true", "yes", "on"}


def _env_float(name: str, default: float) -> float:
    raw = os.getenv(name)
    if raw is None or str(raw).strip() == "":
        return default
    try:
        return float(str(raw).strip())
    except ValueError:
        logger.warning("%s=%r is not a number; using %s", name, raw, default)
        return default


def resolve_base_url(raw: str | None = None) -> str:
    """Resolve and normalize the Acunetix API root.

    Reads ``ACUNETIX_URL`` first, then ``ACUNETIX_BASE_URL``. Accepts the bare
    console address, a trailing slash, or a browser-style fragment
    (``https://host:3443/#/dashboard``) and always returns the ``/api/v1`` root.
    A sub-path installation (``https://host/acunetix/api/v1``) is preserved.

    Returns an empty string when nothing is configured.
    """
    candidate = (
        raw
        or os.getenv("ACUNETIX_URL")
        or os.getenv("ACUNETIX_BASE_URL")
        or ""
    ).strip()
    if not candidate:
        return ""

    # Drop a browser-console fragment or query string (…/index.php#/dashboard).
    candidate = candidate.split("#", 1)[0].split("?", 1)[0].strip()
    if not candidate:
        return ""

    if "://" not in candidate:
        candidate = f"https://{candidate}"

    candidate = candidate.rstrip("/")
    lowered = candidate.lower()

    if lowered.endswith("/api/v1"):
        return candidate
    if lowered.endswith("/api"):
        return f"{candidate}/v1"
    return f"{candidate}/api/v1"


def _error_detail(response: httpx.Response) -> str:
    """Best-effort human-readable error body from an Acunetix response."""
    try:
        payload = response.json()
    except ValueError:
        return (response.text or "").strip()[:500] or response.reason_phrase

    if isinstance(payload, dict):
        for key in ("message", "error", "detail", "Message"):
            value = payload.get(key)
            if value:
                return str(value)[:500]
    return str(payload)[:500]


class AcunetixClient:
    """Thin synchronous wrapper around the Acunetix Premium v1 API."""

    def __init__(
        self,
        base_url: str | None = None,
        api_key: str | None = None,
        verify_tls: bool | None = None,
        timeout: float | None = None,
    ):
        self.base_url = resolve_base_url(base_url)
        self.api_key = (api_key or os.getenv("ACUNETIX_API_KEY") or "").strip()
        if not self.base_url:
            raise AcunetixError(
                "ACUNETIX_URL is not set. Point it at your Acunetix console, "
                "e.g. https://acunetix.example.com:3443"
            )
        if not self.api_key:
            raise AcunetixError(
                "ACUNETIX_API_KEY is not set. Generate an API key in Acunetix "
                "(Profile → API key) and add it to the environment."
            )

        # On-prem installs normally present a self-signed certificate, so TLS
        # verification is off unless explicitly enabled. Every Acunetix setting is
        # read from the environment — no URL, key or limit lives in this module.
        if verify_tls is None:
            verify_tls = _env_bool("ACUNETIX_VERIFY_TLS", False)
        if timeout is None:
            timeout = _env_float("ACUNETIX_HTTP_TIMEOUT_SEC", 30.0)

        self._client = httpx.Client(
            base_url=self.base_url,
            headers={
                "X-Auth": self.api_key,
                "Content-Type": "application/json",
                "Accept": "application/json",
            },
            verify=verify_tls,
            timeout=timeout,
        )

    # ── lifecycle ─────────────────────────────────────────────────────────────

    def __enter__(self) -> "AcunetixClient":
        return self

    def __exit__(self, *_exc) -> None:
        self.close()

    def close(self) -> None:
        try:
            self._client.close()
        except Exception:  # pragma: no cover - defensive
            pass

    # ── internals ─────────────────────────────────────────────────────────────

    def _request(self, method: str, path: str, **kwargs) -> dict:
        try:
            response = self._client.request(method, path, **kwargs)
        except httpx.HTTPError as exc:
            raise AcunetixError(f"Could not reach Acunetix at {self.base_url}{path}: {exc}") from exc

        if response.status_code >= 400:
            raise AcunetixError(
                f"Acunetix {method} {path} returned {response.status_code}: {_error_detail(response)}"
            )

        if not response.content:
            return {}
        try:
            payload = response.json()
        except ValueError:
            return {}
        return payload if isinstance(payload, dict) else {"data": payload}

    # ── targets ───────────────────────────────────────────────────────────────

    def find_target_by_address(self, address: str) -> str | None:
        """Return the id of an existing target with exactly this address, if any.

        Acunetix' ``q`` parameter is a structured filter expression
        (``q=(criticality:equals:high)``), not a free-text search, so passing a
        raw URL makes ``GET /targets`` fail with ``400 Validation errors``.
        Pagination is cursor-based (``l`` limit + ``c`` cursor), so we page
        through the targets and match on the address client-side.
        """
        wanted = (address or "").strip().rstrip("/").lower()
        if not wanted:
            return None

        cursor: str | None = ""
        # Hard cap so a broken pagination cursor can never loop forever.
        for _ in range(200):
            params: dict = {"l": 100}
            if cursor:
                params["c"] = cursor
            payload = self._request("GET", "/targets", params=params)

            for target in payload.get("targets") or []:
                candidate = str(target.get("address") or "").strip().rstrip("/").lower()
                if candidate == wanted:
                    return str(target.get("target_id") or "") or None

            pagination = payload.get("pagination") or {}
            cursor = str(
                pagination.get("cursor") or pagination.get("c") or ""
            ).strip() or None
            if not cursor:
                break
        return None

    def create_target(self, address: str, description: str = "", criticality: int = 10) -> str:
        """Create (or reuse) an Acunetix target and return its ``target_id``."""
        existing = self.find_target_by_address(address)
        if existing:
            logger.info("Reusing existing Acunetix target %s for %s", existing, address)
            return existing

        payload = self._request(
            "POST",
            "/targets",
            json={
                "address": address,
                "description": description or f"ShieldStat web scan for {address}",
                "criticality": criticality,
            },
        )
        target_id = str(payload.get("target_id") or "").strip()
        if not target_id:
            raise AcunetixError("Acunetix did not return a target_id when creating the target.")
        logger.info("Created Acunetix target %s for %s", target_id, address)
        return target_id

    # ── scanning profiles ─────────────────────────────────────────────────────

    def list_profiles(self) -> list[dict]:
        """Return the scanning profiles Acunetix exposes."""
        payload = self._request("GET", "/scanning_profiles")
        return payload.get("scanning_profiles") or []

    def resolve_profile_id(self) -> str:
        """Pick the scanning profile to use.

        ``ACUNETIX_PROFILE_ID`` wins when set. Otherwise a profile whose name
        looks like a full scan is used. When nothing matches, an empty string is
        returned so the caller can omit ``profile_id`` and let Acunetix apply its
        own default (normally *Full Scan*) — blindly using the first returned
        profile can select a crawl-only one that reports no vulnerabilities.
        """
        configured = (os.getenv("ACUNETIX_PROFILE_ID") or "").strip()
        if configured:
            return configured

        profiles = self.list_profiles()
        if not profiles:
            raise AcunetixError(
                "Acunetix reported no scanning profiles. Set ACUNETIX_PROFILE_ID "
                "to the profile you want to use."
            )

        for profile in profiles:
            name = str(profile.get("name") or "").lower()
            if "full" in name:
                return str(profile.get("profile_id") or "").strip()

        available = ", ".join(
            sorted({str(p.get("name") or "").strip() for p in profiles if p.get("name")})
        )
        logger.warning(
            "No Acunetix scanning profile matched a full scan; leaving the profile "
            "unset so Acunetix uses its default. Available profiles: %s. Pin one "
            "with ACUNETIX_PROFILE_ID to be explicit.",
            available,
        )
        return ""

    # ── scans ─────────────────────────────────────────────────────────────────

    def start_scan(self, target_id: str, profile_id: str | None = None) -> str:
        """Start a scan immediately (not scheduled) and return its ``scan_id``.

        ``profile_id`` is omitted from the request when it resolves to empty, so
        Acunetix falls back to its own default profile.
        """
        profile = profile_id if profile_id is not None else self.resolve_profile_id()
        profile = str(profile or "").strip()

        body: dict = {
            "target_id": target_id,
            "schedule": {
                "disable": False,
                "start_date": None,
                "time_sensitive": False,
            },
        }
        if profile:
            body["profile_id"] = profile

        payload = self._request("POST", "/scans", json=body)
        scan_id = str(payload.get("scan_id") or "").strip()
        if not scan_id:
            raise AcunetixError("Acunetix did not return a scan_id when starting the scan.")
        logger.info("Started Acunetix scan %s for target %s", scan_id, target_id)
        return scan_id

    def abort_scan(self, scan_id: str) -> None:
        """Ask Acunetix to stop a running scan (best effort)."""
        try:
            self._request("POST", f"/scans/{scan_id}/abort")
        except AcunetixError:
            logger.warning("Could not abort Acunetix scan %s", scan_id, exc_info=True)
