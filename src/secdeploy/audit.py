"""Per-deploy audit artifacts — compliance (CMMC) evidence of what was stood up.

Every real (non-``--dry-run``) ``secdeploy deploy`` writes a record of exactly what happened:
which components landed on this resource (pinned ref + resolved SHA), what addressing was
generated (the ``secdns`` zone, and — when SecRouter is on this resource — its SecLLM backend
pool), which security-relevant authorizations were made (the SecCert trust anchor, the resolver
pointed at ``secdns``), and the flags in effect. This is the same spirit as ``bundle.py``'s
``BUNDLE-INFO.txt`` — a plain, inspectable record — but per-deploy and dual-format: a machine
JSON (``json`` module, stdlib only) an auditor's tooling can parse, plus a human ``.txt``
summary for a reviewer.

The SecLLM backend pool matters for CMMC evidence specifically because SecRouter is
*auto-configured* to egress to every instance in that pool (``SECROUTER_SECLLM_ENDPOINTS`` —
see :mod:`secdeploy.wiring`) — inference traffic that may carry CUI. Recording those hosts here
gives the operator a declared, dated egress boundary to cite in the SSP, rather than having to
reconstruct it after the fact from `topology.toml`.

Deliberately free of target/OS specifics (like :mod:`secdeploy.wiring`) — callers (the targets)
compute what they know (services placed, resolved SHAs, whether a confirm-gated authorization
step actually ran) and hand it in; this module just assembles and writes the record.
"""

from __future__ import annotations

import hashlib
import json
import re
from datetime import datetime, timezone
from pathlib import Path
from typing import TYPE_CHECKING

from . import wiring

if TYPE_CHECKING:
    from .manifest import Manifest
    from .topology import Topology

SCHEMA_VERSION = 1
# The label used for the resource when a deploy has no topology.toml (single-host mode) —
# matches Topology.single_host's default resource name, so the label reads the same whether
# or not the caller bothered to synthesize a Topology for the audit.
SINGLE_HOST_RESOURCE = "local"
SINGLE_HOST_ADDRESS = "127.0.0.1"

# ── deploy-audit hash chain (AU-3.3.8 — protect audit information) ─────────────────────────
#
# write_deploy_audit() has always written ONE fixed-name snapshot per target+resource
# (deploy-<target>-<resource>.json/.txt — see audit_paths), overwritten by every redeploy. That
# is fine as a "what does this resource look like right now" artifact but useless as tamper-
# evidence: overwriting destroys the previous record, so there is nothing left to chain INTO.
#
# So each real deploy ALSO appends an immutable, timestamped copy of the same record —
# deploy-<target>-<resource>-<UTC timestamp>.json — carrying two extra fields: `prevHash` (the
# SHA-256 of the previous such file's canonical content for the same target+resource, or the
# literal string "GENESIS" if this is the first one) and `hash` (the SHA-256 of THIS record's
# own canonical content, `prevHash` included, `hash` itself excluded — you cannot hash yourself).
# The fixed-name snapshot gets the identical content (so it always shows its own place in the
# chain too), but is never itself part of the chain sequence :func:`verify_chain` walks — a
# redeploy overwriting it doesn't break anything, since the timestamped file already captured it.
#
# Old files from before this existed (or the fixed-name snapshot itself) carry no `prevHash`/
# `hash` and don't match the timestamped-filename pattern below, so they're invisible to
# :func:`verify_chain`/:func:`verify_all` — "grandfathered": the chain simply starts fresh at
# GENESIS the first time a real deploy runs under this feature, rather than erroring on history
# it has no way to validate.
CHAIN_TS_FMT = "%Y%m%dT%H%M%S%f"  # UTC, microsecond resolution — collision-safe even for
                                   # back-to-back deploys in a fast test/CI loop
GENESIS = "GENESIS"
_CHAIN_RE = re.compile(r"^deploy-(?P<stem>.+)-(?P<ts>\d{8}T\d{12}Z)\.json$")


def _canonical(record: dict[str, object]) -> str:
    """Deterministic serialization used for hashing — compact, key order as inserted (never
    re-sorted: :func:`write_deploy_audit` always builds ``record`` the same way for the same
    inputs, so this is reproducibly the same text for the same logical content)."""
    return json.dumps(record, separators=(",", ":"))


def _chain_file_path(out_dir: str | Path, target: str, resource: str | None, now: datetime) -> Path:
    """Where THIS deploy's immutable, timestamped chain entry gets written — see the module
    docstring above. Distinct from :func:`audit_paths`'s fixed-name snapshot; never overwritten."""
    stem = f"deploy-{target}-{_resource_label(resource)}-{now.strftime(CHAIN_TS_FMT)}Z"
    return Path(out_dir) / "audit" / f"{stem}.json"


def _existing_chain_files(out_dir: str | Path, target: str, resource: str | None) -> list[Path]:
    """Every already-written chain entry for this target+resource, oldest first (the timestamp
    format sorts lexicographically = chronologically). Empty if none exist yet — either a fresh
    deploy (chain starts at GENESIS) or only grandfathered pre-chain files are present."""
    d = Path(out_dir) / "audit"
    if not d.is_dir():
        return []
    prefix = f"deploy-{target}-{_resource_label(resource)}-"
    matches = []
    for p in d.iterdir():
        m = _CHAIN_RE.match(p.name)
        if m and p.name.startswith(prefix):
            matches.append(p)
    return sorted(matches)


def _verify_files(files: list[Path]) -> dict[str, object]:
    """Walk an already-sorted (chronological) list of chain files, recomputing each entry's
    hash and checking the prevHash link to the one before it. Returns
    ``{"ok", "checked", "brokenAt"}`` — ``checked`` is how many entries verified clean before a
    break (or all of them, if ``ok``); ``brokenAt`` is the 1-based position of the first bad
    entry (its path), or ``None`` when everything checks out."""
    prev_hash = GENESIS
    for i, f in enumerate(files, 1):
        try:
            entry = json.loads(f.read_text())
        except (OSError, ValueError) as exc:
            return {"ok": False, "checked": i - 1, "brokenAt": f"{f} (unreadable: {exc})"}
        if entry.get("prevHash") != prev_hash:
            return {"ok": False, "checked": i - 1, "brokenAt": str(f)}
        stored_hash = entry.get("hash")
        check = {k: v for k, v in entry.items() if k != "hash"}
        if hashlib.sha256(_canonical(check).encode()).hexdigest() != stored_hash:
            return {"ok": False, "checked": i - 1, "brokenAt": str(f)}
        prev_hash = stored_hash
    return {"ok": True, "checked": len(files), "brokenAt": None}


def verify_chain(out_dir: str | Path, target: str, resource: str | None = None) -> dict[str, object]:
    """Verify one target+resource's deploy-audit hash chain — walks its timestamped chain
    entries chronologically (see the module docstring), recomputing and cross-checking every
    ``hash``/``prevHash``. Returns ``{"ok": bool, "checked": int, "brokenAt": str | None}``.
    Empty/no chain entries yet (a fresh out/, or only grandfathered pre-chain files) is ``ok``
    with ``checked=0`` — nothing to verify is not a failure."""
    return _verify_files(_existing_chain_files(out_dir, target, resource))


def verify_all(out_dir: str | Path) -> dict[str, object]:
    """Verify every target+resource's chain found under ``<out_dir>/audit/`` — what
    ``secdeploy audit verify`` runs. Returns
    ``{"ok": bool, "checked": int, "brokenAt": str | None, "targets": {"<target>-<resource>":
    {...same shape as :func:`verify_chain`...}, ...}}`` — ``ok``/``checked``/``brokenAt`` are
    the aggregate across every discovered chain (``brokenAt`` names the FIRST broken one found);
    ``targets`` carries the per-chain detail. Directories with no chain files at all (nothing
    chained yet) report ``ok=True, checked=0, targets={}`` — never a failure."""
    d = Path(out_dir) / "audit"
    groups: dict[str, list[Path]] = {}
    if d.is_dir():
        for p in sorted(d.iterdir()):
            m = _CHAIN_RE.match(p.name)
            if m:
                groups.setdefault(m.group("stem"), []).append(p)
    ok = True
    checked = 0
    broken_at: str | None = None
    targets: dict[str, object] = {}
    for stem, files in sorted(groups.items()):
        result = _verify_files(sorted(files))
        targets[stem] = result
        checked += result["checked"]
        if not result["ok"] and ok:
            ok = False
            broken_at = f"{stem}: {result['brokenAt']}"
    return {"ok": ok, "checked": checked, "brokenAt": broken_at, "targets": targets}


def _resource_label(resource: str | None) -> str:
    return resource or SINGLE_HOST_RESOURCE


def audit_paths(out_dir: str | Path, target: str, resource: str | None) -> tuple[Path, Path]:
    """The ``(json_path, txt_path)`` a deploy audit for ``target``/``resource`` would use.

    Shared by :func:`write_deploy_audit` and :func:`dry_run_note` so the preview and the real
    artifact can never name different files.
    """
    stem = f"deploy-{target}-{_resource_label(resource)}"
    d = Path(out_dir) / "audit"
    return d / f"{stem}.json", d / f"{stem}.txt"


def _component_records(
    manifest: "Manifest", names: list[str], shas: dict[str, str]
) -> list[dict[str, object]]:
    records = []
    for name in names:
        c = manifest.components.get(name)
        if c is None:
            continue
        records.append({
            "name": name,
            "kind": c.kind,
            "tier": c.tier,
            "ref": c.ref,
            "sha": shas.get(name),
            "role": c.role,
        })
    return records


def _addressing_record(
    topology: "Topology | None", without: list[str], addressing: dict[str, object] | None,
    services: list[str],
) -> dict[str, object]:
    if topology is None:
        return {
            "secdns_zone": {"path": None, "record_count": 0},
            "secrouter_secllm_backend_pool": [],
            "note": "single-host mode (no topology.toml) — no cross-host addressing generated this run",
        }
    zone_path = str(addressing["zone"]) if addressing else None
    pool = wiring.secllm_endpoints(topology, without) if "secrouter" in services else []
    return {
        "secdns_zone": {"path": zone_path, "record_count": len(topology.zone(without))},
        "secrouter_secllm_backend_pool": pool,
    }


def _authorizations_record(
    topology: "Topology | None", without: list[str], services: list[str], *,
    trust_anchor_added: bool, resolver_configured: bool, secllm_auth_enabled: bool,
    egress_rules_file: str | None, secagent_enabled: bool,
) -> dict[str, object]:
    # Single-sourced from the SAME function that produced secrouter-egress.json (see
    # write_addressing) — the audit's host list can never drift from the generated artifact.
    rules = (
        wiring.secrouter_egress_rules(topology, without)
        if topology is not None and "secrouter" in services else []
    )
    hosts: list[str] = list(rules[0]["allowedHost"]) if rules else []
    note = (
        "SecRouter is authorized — via the generated secrouter-egress.json allow-list "
        "(SECROUTER_EGRESS_FILE) and/or its own SECROUTER_SECLLM_ENDPOINTS turnkey intake — "
        "to egress to its SecLLM backend pool for inference traffic (may carry CUI); cite this "
        "as SecRouter's declared egress boundary in the CMMC SSP / network boundary diagram."
        if hosts else
        "no SecLLM backend pool wired to SecRouter on this run — no egress auto-authorized"
    )
    return {
        "seccert_trust_anchor_added": bool(trust_anchor_added),
        "resolver_pointed_at_secdns": bool(resolver_configured),
        # SecRouter<->SecLLM shared bearer token (SECLLM_API_TOKEN / SECROUTER_SECLLM_TOKEN) —
        # boolean only. The value itself is NEVER recorded in this artifact.
        "secllm_inference_auth_enabled": bool(secllm_auth_enabled),
        "egress": {
            "secllm_backend_pool_hosts": hosts,
            "rules_file": egress_rules_file,
            "note": note,
        },
        # SecAgent (the on-demand pi harness, --with-agent) — again booleans/a fixed identifier
        # only; the SecSSO client secret is NEVER recorded here.
        "secagent_enabled": bool(secagent_enabled),
        # secagent's LLM traffic is wired to SecRouter (never directly to SecLLM) whenever
        # secagent is enabled at all — see Topology.env_for's secagent branch — so this is the
        # same underlying fact as secagent_enabled, named separately because it is a
        # distinct claim an auditor may want to check (governed/audited inference path).
        "secagent_llm_at_secrouter": bool(secagent_enabled),
        # The service-account subject the generated secrouter-oidc.json fragment declares
        # (see wiring.secrouter_oidc_config) — what secdeploy RECOMMENDS the operator add to
        # security.oidc.serviceSubjects, not a confirmed fact about their live secrouter.
        # config.json (secdeploy cannot inspect that hand-authored file).
        "oidc_service_subject": "svc-secagent" if secagent_enabled else None,
    }


def _render_txt(record: dict[str, object]) -> str:
    suite, res = record["suite"], record["resource"]
    lines = [
        "SecDeploy — deployment audit",
        "=============================",
        f"generated_at:  {record['generated_at']}",
        f"suite:         {suite['version']} (released {suite['released']})",
        f"target:        {record['target']}",
        f"resource:      {res['name']} ({res['address']})",
        "",
        "components deployed on this resource:",
    ]
    components = record["components"]
    if components:
        for c in components:
            sha = (c["sha"] or "?")[:12]
            lines.append(f"  - {c['name']:<12} {c['ref']:<10} {sha:<13} [{c['kind']}]  {c['role']}")
    else:
        lines.append("  (none)")

    addr = record["addressing"]
    zone = addr["secdns_zone"]
    zone_where = f"({zone['path']})" if zone["path"] else "(not generated this run)"
    lines += ["", "addressing:", f"  secdns zone:  {zone['record_count']} record(s)  {zone_where}"]
    pool = addr.get("secrouter_secllm_backend_pool") or []
    if pool:
        lines.append("  secrouter → secllm backend pool (SECROUTER_SECLLM_ENDPOINTS):")
        lines += [f"    - {u}" for u in pool]
    else:
        lines.append("  secrouter → secllm backend pool: (not applicable on this resource/run)")

    auth = record["authorizations"]
    lines += [
        "",
        "security-relevant authorizations:",
        f"  SecCert trust anchor added:       {'yes' if auth['seccert_trust_anchor_added'] else 'no'}",
        f"  resolver pointed at secdns:       {'yes' if auth['resolver_pointed_at_secdns'] else 'no'}",
        f"  secllm inference auth enabled:    {'yes' if auth['secllm_inference_auth_enabled'] else 'no'}"
        "  (shared bearer token — value never recorded here)",
        "  egress (SecRouter -> SecLLM pool): "
        + (", ".join(auth["egress"]["secllm_backend_pool_hosts"]) or "(none)"),
    ]
    if auth["egress"].get("rules_file"):
        lines.append(f"    rules file: {auth['egress']['rules_file']}")
    lines.append(f"    note: {auth['egress']['note']}")
    lines += [
        f"  SecAgent harness enabled:          {'yes' if auth['secagent_enabled'] else 'no'}",
        f"  SecAgent LLM routed via SecRouter: {'yes' if auth['secagent_llm_at_secrouter'] else 'no'}",
        f"  OIDC service subject declared:     {auth['oidc_service_subject'] or '(none)'}"
        "  (recommendation for security.oidc.serviceSubjects — see secrouter-oidc.json)",
    ]

    lines += ["", "flags in effect:"]
    for k, v in record["flags"].items():
        v_str = (", ".join(v) or "(none)") if isinstance(v, list) else ("yes" if v else "no")
        lines.append(f"  {k:<20} {v_str}")

    if "hash" in record:
        lines += [
            "",
            "audit chain (AU-3.3.8 — verify with `secdeploy audit verify`):",
            f"  prevHash: {record.get('prevHash', '?')}",
            f"  hash:     {record['hash']}",
        ]
    return "\n".join(lines) + "\n"


def write_deploy_audit(
    manifest: "Manifest",
    topology: "Topology | None",
    resource: str | None,
    out_dir: str | Path,
    *,
    target: str,
    services: list[str],
    shas: dict[str, str],
    stacks: list[str] | None = None,
    flags: dict[str, object] | None = None,
    without: list[str] | None = None,
    addressing: dict[str, object] | None = None,
    trust_anchor_added: bool = False,
    resolver_configured: bool = False,
    secllm_auth_enabled: bool = False,
    secagent_enabled: bool = False,
    now: datetime | None = None,
) -> Path:
    """Write the JSON + ``.txt`` audit artifacts for one real deploy; return the JSON path.

    ``services``/``stacks`` are the component names the caller (a target's ``deploy()``)
    already determined belong on ``resource`` this run; ``shas`` is normally
    ``targets.common.resolved_shas(manifest, work)``. ``addressing`` is the dict
    :func:`secdeploy.wiring.write_addressing` returned this run (``None`` if no topology-driven
    addressing was generated — e.g. single-host mode); when it carries an ``"egress"`` key
    (the generated ``secrouter-egress.json``'s path), the audit's egress section points at it.
    ``topology``/``resource`` may both be ``None`` for single-host mode; the artifact then
    reports the conventional single-host resource label/address and an empty addressing
    section (nothing cross-host was generated).

    ``secllm_auth_enabled`` records (boolean only) whether the SecRouter<->SecLLM shared bearer
    token (``SECLLM_API_TOKEN``/``SECROUTER_SECLLM_TOKEN`` — see
    :func:`secdeploy.wiring.secllm_shared_token`) is wired for this deploy. The token VALUE is
    never accepted by this function and never appears in the artifact.

    ``secagent_enabled`` records (boolean only) whether this deploy installed SecAgent's on-demand
    pi harness (``--with-agent``) — see ``secagent_enabled``/``secagent_llm_at_secrouter``/
    ``oidc_service_subject`` in the ``authorizations`` section. Like ``secllm_auth_enabled``, no
    secret (the SecSSO client secret) is ever accepted by this function or appears in the artifact.

    ``now`` is injectable (default :func:`datetime.now` in UTC) so callers get a deterministic,
    testable timestamp instead of wall-clock time.

    Also appends this deploy to the target+resource's hash chain (AU-3.3.8 — see the module
    docstring above): the returned/written record gains ``prevHash``/``hash`` fields, and an
    immutable, timestamped copy lands alongside the fixed-name snapshot this always wrote —
    verify with :func:`verify_chain`/:func:`verify_all` or ``secdeploy audit verify``.
    """
    now = now or datetime.now(timezone.utc)
    without = list(without or [])
    stacks = list(stacks or [])
    flags = dict(flags or {})
    resource_name = _resource_label(resource)
    resource_address = (
        topology.resources[resource].address
        if topology is not None and resource is not None and resource in topology.resources
        else SINGLE_HOST_ADDRESS
    )
    egress_rules_file = (
        str(addressing["egress"]) if addressing and addressing.get("egress") else None
    )

    record: dict[str, object] = {
        "schema_version": SCHEMA_VERSION,
        "generated_at": now.isoformat(),
        "suite": {"version": manifest.suite, "released": manifest.released},
        "target": target,
        "resource": {"name": resource_name, "address": resource_address},
        "components": _component_records(manifest, list(services) + stacks, shas),
        "addressing": _addressing_record(topology, without, addressing, services),
        "authorizations": _authorizations_record(
            topology, without, services,
            trust_anchor_added=trust_anchor_added, resolver_configured=resolver_configured,
            secllm_auth_enabled=secllm_auth_enabled, egress_rules_file=egress_rules_file,
            secagent_enabled=secagent_enabled,
        ),
        "flags": flags,
    }

    # Hash-chain this deploy onto the previous one for this SAME target+resource (see the
    # module docstring) — GENESIS if none exists yet (first real deploy here, or only
    # grandfathered pre-chain files are present). prevHash is set before hash is computed;
    # hash covers everything ELSE in the record (it cannot cover itself).
    prev_files = _existing_chain_files(out_dir, target, resource)
    record["prevHash"] = (
        json.loads(prev_files[-1].read_text()).get("hash", GENESIS) if prev_files else GENESIS
    )
    record["hash"] = hashlib.sha256(_canonical(record).encode()).hexdigest()

    chain_path = _chain_file_path(out_dir, target, resource, now)
    chain_path.parent.mkdir(parents=True, exist_ok=True)
    chain_path.write_text(json.dumps(record, indent=2) + "\n")

    json_path, txt_path = audit_paths(out_dir, target, resource)
    json_path.parent.mkdir(parents=True, exist_ok=True)
    json_path.write_text(json.dumps(record, indent=2) + "\n")
    txt_path.write_text(_render_txt(record))
    return json_path


def dry_run_note(
    out_dir: str | Path, target: str, resource: str | None, *,
    component_count: int, trust_anchor: bool, resolver: bool,
) -> str:
    """One-line preview of the audit artifact a real run would write — printed on
    ``--dry-run`` instead of writing anything (dry-run stays side-effect-light)."""
    json_path, _ = audit_paths(out_dir, target, resource)
    return (
        f"audit: a real run would write {json_path} (+ .txt) — "
        f"{component_count} component(s) on {_resource_label(resource)!r}, "
        f"trust_anchor={'yes' if trust_anchor else 'no'}, resolver={'yes' if resolver else 'no'}"
    )
