"""Encrypted backup archives — the crypto + manifest primitives for `secdeploy backup`.

The suite's state (Authentik + SecChat Postgres, SecRouter's hash-chained SQLite, SecAgent's
audit log, and — crown jewels — SecCert's CA private keys) is coupled to its secrets:
``SECCERT_CA_PASSPHRASE`` decrypts the CA keys, and each stack's ``.env`` holds the DB
credentials its dump is restored with. So a backup is data + secrets in ONE archive, and it
MUST be encrypted.

Encryption is **public-key**: the plaintext ``.tar`` is encrypted to an X.509 **recipient cert**
via OpenSSL CMS (RFC 5652 EnvelopedData) with **AES-256-CBC** content encryption. The recipient's
private key is held OFFLINE and is only needed to restore — nothing secret sits on the backup host,
which is what makes an unattended backup safe. AES-256 + RSA/EC are FIPS-approved (unlike age's
ChaCha20); on the Fedora host OpenSSL's FIPS provider does the work. CBC (not GCM/AuthEnveloped) is
the content cipher deliberately: it is the portable common denominator (macOS ships LibreSSL, whose
CMS cannot decrypt GCM AuthEnvelopedData), and integrity is provided out-of-band by the manifest's
SHA-256 of the plaintext, which ``restore`` verifies after decrypt.

OS-agnostic, like :mod:`secdeploy.audit`: the targets assemble WHAT was captured and hand it in;
this module encrypts, hashes, and writes the record. Secrets themselves are NEVER written to the
manifest — only names, sizes, hashes, and the recipient cert fingerprint.
"""

from __future__ import annotations

import hashlib
import json
import sys
import tarfile
from datetime import datetime, timezone
from pathlib import Path

from . import process as P

SCHEMA_VERSION = 1
CIPHER = "cms-aes-256-cbc"  # CMS EnvelopedData, AES-256-CBC content — portable + FIPS-approved
SINGLE_HOST_RESOURCE = "local"


def _resource_label(resource: str | None) -> str:
    return resource or SINGLE_HOST_RESOURCE


def backup_paths(out_dir: str | Path, target: str, resource: str | None, ts: str) -> tuple[Path, Path, Path]:
    """The ``(archive, manifest_json, manifest_txt)`` paths a backup for this target/resource uses.

    ``ts`` is a caller-supplied UTC timestamp string (``YYYYmmddTHHMMSSZ``) — passed in, not read
    from the clock, so a dry-run preview and the real artifact name the same files, and tests are
    deterministic (this module, like :mod:`audit`, never calls the clock itself)."""
    stem = f"secsuite-{target}-{_resource_label(resource)}-{ts}"
    d = Path(out_dir) / "backups"
    return d / f"{stem}.tar.cms", d / f"{stem}.manifest.json", d / f"{stem}.manifest.txt"


def openssl_bin() -> str:
    """Locate an ``openssl`` (fail closed if absent). On the Fedora host this is OpenSSL 3 with the
    FIPS provider; on macOS it is LibreSSL (which is why the content cipher is CBC, not GCM)."""
    exe = P.which("openssl")
    if not exe:
        P.die("openssl not found — required to encrypt/decrypt backups")
    return exe


def sha256_file(path: str | Path) -> str:
    h = hashlib.sha256()
    with open(path, "rb") as f:
        for chunk in iter(lambda: f.read(1 << 20), b""):
            h.update(chunk)
    return h.hexdigest()


def cert_fingerprint(recipient_cert: str | Path) -> str:
    """SHA-256 fingerprint of the recipient cert (``AA:BB:...``), recorded in the manifest so a
    restore can confirm which key is needed without the cert itself being a secret."""
    out = P.run(
        [openssl_bin(), "x509", "-in", str(recipient_cert), "-noout", "-fingerprint", "-sha256"],
        capture=True,
    ).stdout.strip()
    return out.split("=", 1)[1] if "=" in out else out


def encrypt_archive(tar_path: str | Path, recipient_cert: str | Path, out_cms: str | Path) -> None:
    """Encrypt ``tar_path`` to ``out_cms`` (CMS EnvelopedData / AES-256-CBC, DER) for the recipient
    cert's public key. Only the public cert is needed here — the private key stays offline."""
    Path(out_cms).parent.mkdir(parents=True, exist_ok=True)
    P.run([
        openssl_bin(), "cms", "-encrypt", "-aes-256-cbc", "-binary",
        "-in", str(tar_path), "-outform", "DER", "-out", str(out_cms), "-recip", str(recipient_cert),
    ])


def decrypt_archive(
    cms_path: str | Path, key: str | Path, out_tar: str | Path, recipient_cert: str | Path | None = None,
) -> None:
    """Decrypt ``cms_path`` to ``out_tar`` with the recipient's private ``key`` (the offline key).
    ``recipient_cert`` is optional (helps select the recipient for a multi-recipient archive)."""
    cmd = [openssl_bin(), "cms", "-decrypt", "-inform", "DER", "-in", str(cms_path),
           "-inkey", str(key), "-out", str(out_tar)]
    if recipient_cert:
        cmd += ["-recip", str(recipient_cert)]
    P.run(cmd)


def write_backup_manifest(
    out_dir: str | Path, target: str, resource: str | None, *,
    suite: dict[str, str], components: list[dict], archive_name: str,
    plaintext_sha256: str, archive_sha256: str, plaintext_bytes: int, archive_bytes: int,
    recipient_fingerprint: str, ts: str, now: datetime,
) -> tuple[Path, Path]:
    """Write the ``(json, txt)`` backup manifest. Records ONLY metadata — component names + what
    each captured (names, never secret values), sizes, the plaintext SHA-256 (restore verifies it),
    the cipher, and the recipient cert fingerprint. Never a secret. ``now`` is injectable for tests."""
    record = {
        "schema_version": SCHEMA_VERSION,
        "generated_at": now.astimezone(timezone.utc).isoformat(),
        "kind": "backup",
        "target": target,
        "resource": _resource_label(resource),
        "suite": suite,
        "archive": {
            "name": archive_name,
            "cipher": CIPHER,
            "recipient_cert_sha256": recipient_fingerprint,
            "plaintext_sha256": plaintext_sha256,
            "encrypted_sha256": archive_sha256,
            "plaintext_bytes": plaintext_bytes,
            "encrypted_bytes": archive_bytes,
        },
        "components": components,  # [{name, kind, captured: [names]}] — never secret values
    }
    _, json_path, txt_path = backup_paths(out_dir, target, resource, ts)
    json_path.parent.mkdir(parents=True, exist_ok=True)
    json_path.write_text(json.dumps(record, indent=2) + "\n")
    txt_path.write_text(_render_txt(record))
    return json_path, txt_path


def _render_txt(record: dict) -> str:
    a = record["archive"]
    lines = [
        "SecRouter suite — encrypted backup",
        f"  generated:  {record['generated_at']}",
        f"  target:     {record['target']} / {record['resource']}",
        f"  suite:      {record['suite'].get('version', '?')}",
        f"  archive:    {a['name']}",
        f"  cipher:     {a['cipher']}",
        f"  recipient:  {a['recipient_cert_sha256']}  (restore needs the matching private key)",
        f"  plaintext:  {a['plaintext_bytes']} bytes  sha256={a['plaintext_sha256']}",
        f"  encrypted:  {a['encrypted_bytes']} bytes  sha256={a['encrypted_sha256']}",
        "  components captured:",
    ]
    for c in record["components"]:
        lines.append(f"    - {c['name']} ({c['kind']}): {', '.join(c.get('captured', [])) or '—'}")
    lines.append("")
    lines.append("  This archive contains the suite's DATA + SECRETS + CA keys. Store it like a")
    lines.append("  secret; keep the recipient private key OFFLINE. Restore: secdeploy restore.")
    return "\n".join(lines) + "\n"


def dry_run_note(out_dir: str | Path, target: str, resource: str | None, ts: str) -> str:
    archive, _, _ = backup_paths(out_dir, target, resource, ts)
    return f"[dry-run] would write encrypted backup → {archive} (+ .manifest.json/.txt); no data read."


def format_ts(now: datetime) -> str:
    """The ``YYYYmmddTHHMMSSZ`` UTC stamp used in a backup's filenames. A target computes
    ``now = datetime.now(timezone.utc)`` once and threads both it and ``format_ts(now)`` through
    :func:`stage_to_encrypted_archive` / :func:`write_backup_manifest`, so the archive name and
    the manifest's ``generated_at`` agree. Kept clock-free here (the caller owns the clock) for
    the same testability reason :mod:`audit` is."""
    return now.astimezone(timezone.utc).strftime("%Y%m%dT%H%M%SZ")


def verify_plaintext(tar_path: str | Path, expected_sha256: str) -> None:
    """Fail closed if a decrypted archive's SHA-256 doesn't match the manifest's — the
    out-of-band integrity check that stands in for AEAD (the content cipher is CBC; see the
    module docstring). Called by :func:`unpack_encrypted_archive` right after decrypt."""
    actual = sha256_file(tar_path)
    if actual != expected_sha256:
        P.die(f"backup integrity check FAILED — decrypted plaintext sha256 {actual} != "
              f"manifest {expected_sha256}. The archive is corrupt or was tampered with; refusing to restore.")


def stage_to_encrypted_archive(
    staging_dir: str | Path, out_dir: str | Path, target: str, resource: str | None, *,
    suite: dict[str, str], components: list[dict], recipient_cert: str | Path, ts: str, now: datetime,
) -> tuple[Path, Path, Path]:
    """Package an already-populated ``staging_dir`` into the encrypted backup artifact set.

    tar (plaintext) → sha256 → CMS-encrypt to ``out/backups/…tar.cms`` → sha256 → write the
    ``.manifest.json``/``.txt``. Returns ``(archive, manifest_json, manifest_txt)``. The
    plaintext tar is written to the staging tree's PARENT (the caller's throwaway temp root, so
    it's wiped with everything else) and unlinked here the moment it's encrypted — **no
    plaintext ever lands under ``out/`` or lingers after this returns**. The caller wipes
    ``staging_dir``; nothing secret is left on the backup host once the offline private key is
    the only thing that can open the archive."""
    staging_dir = Path(staging_dir)
    archive, _json_path, _txt_path = backup_paths(out_dir, target, resource, ts)
    stem = archive.name[: -len(".tar.cms")]
    tar_path = staging_dir.parent / f"{stem}.tar"
    with tarfile.open(tar_path, "w") as tf:
        tf.add(staging_dir, arcname=".")
    plaintext_sha256 = sha256_file(tar_path)
    plaintext_bytes = tar_path.stat().st_size
    encrypt_archive(tar_path, recipient_cert, archive)
    tar_path.unlink()  # plaintext never lingers — the encrypted .tar.cms is the only artifact
    archive_sha256 = sha256_file(archive)
    archive_bytes = archive.stat().st_size
    json_path, txt_path = write_backup_manifest(
        out_dir, target, resource, suite=suite, components=components, archive_name=archive.name,
        plaintext_sha256=plaintext_sha256, archive_sha256=archive_sha256,
        plaintext_bytes=plaintext_bytes, archive_bytes=archive_bytes,
        recipient_fingerprint=cert_fingerprint(recipient_cert), ts=ts, now=now,
    )
    return archive, json_path, txt_path


def unpack_encrypted_archive(
    cms_path: str | Path, key: str | Path, dest_dir: str | Path, *,
    manifest_json: str | Path | None = None, recipient_cert: str | Path | None = None,
) -> Path:
    """Decrypt + verify + extract a backup archive into ``dest_dir/unpacked`` (returned).

    Decrypt with the offline private ``key`` → if ``manifest_json`` is given, verify the
    plaintext SHA-256 against it (:func:`verify_plaintext`, fail-closed) BEFORE extracting →
    untar. Extraction uses tarfile's ``data`` filter (Python 3.12+) to refuse absolute paths /
    ``..`` traversal / device nodes even though we authored the archive. The decrypted tar is
    unlinked once extracted; the caller wipes ``dest_dir`` when the restore is done."""
    dest_dir = Path(dest_dir)
    dest_dir.mkdir(parents=True, exist_ok=True)
    tar_path = dest_dir / "archive.tar"
    decrypt_archive(cms_path, key, tar_path, recipient_cert=recipient_cert)
    if manifest_json is not None:
        expected = json.loads(Path(manifest_json).read_text())["archive"]["plaintext_sha256"]
        verify_plaintext(tar_path, expected)
    unpacked = dest_dir / "unpacked"
    unpacked.mkdir(parents=True, exist_ok=True)
    with tarfile.open(tar_path, "r") as tf:
        if sys.version_info >= (3, 12):
            tf.extractall(unpacked, filter="data")
        else:  # pragma: no cover - 3.12+ in CI; the filter is a hardening extra, not required
            tf.extractall(unpacked)
    tar_path.unlink()
    return unpacked
