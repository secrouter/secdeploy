"""``secdeploy evidence`` — fetch each admin-gated component's one-shot CMMC evidence bundle
(``/admin/api/evidence``) from a REACHABLE deployment, and bundle those responses together with
this host's own deploy-audit hash-chain verify result (see :mod:`secdeploy.audit`) into
``out/evidence/suite-evidence-<date>.json``.

Unlike the rest of secdeploy (which generates deploy-time config from the manifest/topology),
this module is a CLIENT: it dials each component's real, running ``/admin/api/evidence`` endpoint
over the network, using the suite URLs the active topology/site already knows (see
:meth:`secdeploy.topology.Topology.urls`) — so it needs an actually-reachable deployment to
produce anything meaningful (document this in ``--help``/docs/compliance.md; there is no
dry-run/offline mode).

SecRouter exposes this endpoint today (``work/secrouter/src/server.ts`` ``handleEvidence``);
seccert/secllm/secchat/secrecorder are gaining their own in parallel, so every component but
SecRouter is PROBED, never required — a 404 (not implemented yet), a refused/timed-out
connection, or an auth failure is recorded per-component as ``"skipped"``/``"error"`` and never
aborts the whole collection (see :func:`fetch_one`).

Auth: every request needs an admin bearer token — these endpoints are admin-gated exactly like
the rest of ``/admin/api/*``. ``--token`` supplies ONE token used for every component;
``<COMPONENT>_ADMIN_TOKEN`` env vars (e.g. ``SECROUTER_ADMIN_TOKEN``) override it per-component
when set (see :func:`resolve_token`) — useful when components don't share one operator token.
No token VALUE is ever written to the output bundle — only whether one was sent (``"auth"``).
"""

from __future__ import annotations

import json
import os
import urllib.error
import urllib.request
from datetime import date
from pathlib import Path

from . import audit as audit_mod

# Components that expose (or, per the parallel workstream, are gaining) an admin evidence
# endpoint at this same path. SecRouter's exists today; the rest are tolerated absent.
COMPONENTS = ("secrouter", "seccert", "secllm", "secchat", "secrecorder")
EVIDENCE_PATH = "/admin/api/evidence"
DEFAULT_TIMEOUT = 5.0


def token_env_var(component: str) -> str:
    """The per-component admin-token env var this collector honors, e.g.
    ``SECROUTER_ADMIN_TOKEN`` — overrides the shared ``--token`` for just that component."""
    return f"{component.upper()}_ADMIN_TOKEN"


def resolve_token(
    component: str, cli_token: str | None, env: dict[str, str] | None = None,
) -> str | None:
    """A per-component env var (``<COMPONENT>_ADMIN_TOKEN``) wins over the shared ``--token``
    flag — lets an operator override just one component's credential without touching the rest.
    ``None`` when neither is set (the request is sent with no ``Authorization`` header — most
    admin-gated endpoints will then answer 401/403, recorded as ``"error"`` by :func:`fetch_one`,
    never silently as ``"ok"``)."""
    env = os.environ if env is None else env
    return env.get(token_env_var(component)) or cli_token or None


def _http_get(url: str, token: str | None, timeout: float) -> tuple[int, bytes]:
    """The one network seam — tests monkeypatch this directly instead of hitting a real socket.
    Returns ``(status_code, body_bytes)``; raises :class:`urllib.error.HTTPError` for a non-2xx
    response and :class:`urllib.error.URLError` for a connection failure (refused/DNS/timeout),
    exactly like a real dial would."""
    req = urllib.request.Request(url, headers=(
        {"Authorization": f"Bearer {token}"} if token else {}
    ))
    with urllib.request.urlopen(req, timeout=timeout) as resp:  # noqa: S310 (operator-supplied admin URL)
        return resp.status, resp.read()


def fetch_one(
    component: str, base_url: str, *, token: str | None, timeout: float = DEFAULT_TIMEOUT,
) -> dict[str, object]:
    """Probe one component's ``/admin/api/evidence``. Never raises — a component that doesn't
    expose the endpoint yet (404) or is simply unreachable (refused/timeout/DNS) is recorded as
    ``"skipped"`` (not fatal — see the module docstring); an auth failure or any other non-2xx/
    non-JSON response is ``"error"`` (also not fatal to the overall collection, but worth
    flagging); only a parsed 2xx JSON body is ``"ok"``. The token VALUE is never included in the
    result — only ``"auth"`` (whether one was sent)."""
    url = base_url.rstrip("/") + EVIDENCE_PATH
    entry: dict[str, object] = {"url": url, "auth": "token" if token else "none"}
    try:
        status, body = _http_get(url, token, timeout)
    except urllib.error.HTTPError as exc:
        if exc.code == 404:
            entry.update(status="skipped", note="404 — endpoint not available on this component yet")
        elif exc.code in (401, 403):
            entry.update(status="error", note=(
                f"HTTP {exc.code} — admin token missing/rejected "
                f"(see ${token_env_var(component)} or --token)"
            ))
        else:
            entry.update(status="error", note=f"HTTP {exc.code}")
        return entry
    except urllib.error.URLError as exc:
        entry.update(status="skipped", note=f"unreachable: {exc.reason}")
        return entry
    except TimeoutError as exc:
        entry.update(status="skipped", note=f"unreachable: {exc}")
        return entry
    if status != 200:
        entry.update(status="error", note=f"HTTP {status}")
        return entry
    try:
        payload = json.loads(body)
    except ValueError:
        entry.update(status="error", note="response was not valid JSON")
        return entry
    entry.update(status="ok", evidence=payload)
    return entry


def collect(
    urls: dict[str, str], out_dir: str | Path, *,
    token: str | None = None, timeout: float = DEFAULT_TIMEOUT, today: date | None = None,
) -> dict[str, object]:
    """Fetch every reachable component's evidence (``urls`` is normally ``topology.urls(without)``
    — upper-cased component names, the same source every other cross-component URL in
    :mod:`secdeploy.wiring` uses) plus this host's own deploy-audit chain verify result
    (:func:`secdeploy.audit.verify_all`), and write the bundle to
    ``<out_dir>/evidence/suite-evidence-<date>.json``. Returns
    ``{"path": Path, "components": {...}, "audit_chain": {...}}``.

    A component with no single addressable URL in this topology/site (not present, or its tier
    spans multiple resources — see :meth:`Topology.urls`) is recorded ``"not_in_topology"``,
    same "tolerate, never fail the run" spirit as an unreachable one.
    """
    components: dict[str, object] = {}
    for name in COMPONENTS:
        base_url = urls.get(name.upper())
        if not base_url:
            components[name] = {
                "status": "not_in_topology",
                "note": "no single addressable instance in this topology/site",
            }
            continue
        components[name] = fetch_one(
            name, base_url, token=resolve_token(name, token), timeout=timeout,
        )

    chain_result = audit_mod.verify_all(out_dir)
    today = today or date.today()
    bundle = {
        "product": "secdeploy suite evidence",
        "generated_at": today.isoformat(),
        "components": components,
        "deploy_audit_chain": chain_result,
    }
    dest_dir = Path(out_dir) / "evidence"
    dest_dir.mkdir(parents=True, exist_ok=True)
    dest = dest_dir / f"suite-evidence-{today.isoformat()}.json"
    dest.write_text(json.dumps(bundle, indent=2) + "\n")
    return {"path": dest, "components": components, "audit_chain": chain_result}
