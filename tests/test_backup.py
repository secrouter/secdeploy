"""Tests for secdeploy.backup — CMS encrypt/decrypt round-trip + the no-secrets manifest."""

from __future__ import annotations

import json
import subprocess
from datetime import datetime, timezone

import pytest

from secdeploy import backup

FIXED_NOW = datetime(2026, 8, 7, 12, 0, 0, tzinfo=timezone.utc)


def _recipient_keypair(tmp_path, name="bkp"):
    """A throwaway RSA recipient cert + private key (the private key is what stays offline in prod)."""
    cert, key = tmp_path / f"{name}.crt", tmp_path / f"{name}.key"
    subprocess.run(
        ["openssl", "req", "-x509", "-newkey", "rsa:2048", "-keyout", str(key), "-out", str(cert),
         "-days", "1", "-nodes", "-subj", f"/CN=test-{name}"],
        check=True, capture_output=True,
    )
    return cert, key


def test_encrypt_decrypt_round_trip(tmp_path):
    cert, key = _recipient_keypair(tmp_path)
    plain = tmp_path / "plain.tar"
    plain.write_bytes(b"SUITE-STATE-\x00\x01\x02" * 1000)
    enc = tmp_path / "out.tar.cms"
    backup.encrypt_archive(plain, cert, enc)
    assert enc.exists() and enc.read_bytes() != plain.read_bytes()  # actually encrypted
    dec = tmp_path / "dec.tar"
    backup.decrypt_archive(enc, key, dec, recipient_cert=cert)
    assert dec.read_bytes() == plain.read_bytes()
    # the plaintext sha256 a manifest records is exactly what restore recomputes to verify
    assert backup.sha256_file(dec) == backup.sha256_file(plain)


def test_decrypt_with_wrong_key_fails(tmp_path):
    cert, _ = _recipient_keypair(tmp_path, "a")
    _, other_key = _recipient_keypair(tmp_path, "b")
    plain = tmp_path / "p.tar"
    plain.write_bytes(b"x" * 500)
    enc = tmp_path / "e.cms"
    backup.encrypt_archive(plain, cert, enc)
    with pytest.raises(Exception):
        backup.decrypt_archive(enc, other_key, tmp_path / "d.tar")


def test_cert_fingerprint(tmp_path):
    cert, _ = _recipient_keypair(tmp_path)
    fpr = backup.cert_fingerprint(cert)
    assert ":" in fpr and len(fpr.replace(":", "")) == 64  # SHA-256 hex


def test_backup_paths_naming():
    a, j, t = backup.backup_paths("out", "fedora-fips", "core", "20260807T120000Z")
    assert a.name == "secsuite-fedora-fips-core-20260807T120000Z.tar.cms"
    assert j.name.endswith(".manifest.json") and t.name.endswith(".manifest.txt")
    assert a.parent.name == "backups"


def test_format_ts():
    assert backup.format_ts(FIXED_NOW) == "20260807T120000Z"


def test_stage_and_unpack_round_trip(tmp_path):
    """The full packaging path a target uses: a populated staging tree → encrypted archive →
    decrypt+verify+unpack → identical contents, with NO plaintext left behind anywhere."""
    cert, key = _recipient_keypair(tmp_path)
    staging = tmp_path / "work" / "staging"
    (staging / "native").mkdir(parents=True)
    (staging / "native" / "var-seccert.tar.gz").write_bytes(b"CA-PRIVATE-KEY-BLOB")
    (staging / "stacks" / "secsso").mkdir(parents=True)
    (staging / "stacks" / "secsso" / "authentik.sql").write_text("-- dump\n")
    out = tmp_path / "out"
    ts = backup.format_ts(FIXED_NOW)
    archive, json_path, txt_path = backup.stage_to_encrypted_archive(
        staging, out, "fedora-fips", "core", suite={"version": "1.7.0"},
        components=[{"name": "seccert", "kind": "service", "captured": ["var-seccert.tar.gz"]}],
        recipient_cert=cert, ts=ts, now=FIXED_NOW,
    )
    assert archive.exists() and archive.name.endswith(".tar.cms")
    assert txt_path.exists()
    # the encrypted archive must not contain the plaintext, and no plaintext .tar may linger
    assert b"CA-PRIVATE-KEY-BLOB" not in archive.read_bytes()
    assert list(out.glob("**/*.tar")) == []           # nothing plaintext under out/
    assert list(staging.parent.glob("*.tar")) == []   # the temp tar was unlinked after encrypt
    rec = json.loads(json_path.read_text())
    assert rec["archive"]["plaintext_sha256"] and rec["archive"]["encrypted_sha256"]
    # decrypt + verify against the manifest + extract → contents byte-identical
    unpacked = backup.unpack_encrypted_archive(
        archive, key, tmp_path / "restore", manifest_json=json_path, recipient_cert=cert)
    assert (unpacked / "native" / "var-seccert.tar.gz").read_bytes() == b"CA-PRIVATE-KEY-BLOB"
    assert (unpacked / "stacks" / "secsso" / "authentik.sql").read_text() == "-- dump\n"


def test_unpack_fails_closed_on_integrity_mismatch(tmp_path):
    cert, key = _recipient_keypair(tmp_path)
    staging = tmp_path / "work" / "staging"
    (staging / "native").mkdir(parents=True)
    (staging / "native" / "blob").write_bytes(b"data")
    out = tmp_path / "out"
    ts = backup.format_ts(FIXED_NOW)
    archive, json_path, _ = backup.stage_to_encrypted_archive(
        staging, out, "macos", None, suite={"version": "1.7.0"}, components=[],
        recipient_cert=cert, ts=ts, now=FIXED_NOW,
    )
    rec = json.loads(json_path.read_text())
    rec["archive"]["plaintext_sha256"] = "0" * 64  # pretend the archive was tampered with
    json_path.write_text(json.dumps(rec))
    with pytest.raises(SystemExit):  # verify_plaintext → P.die
        backup.unpack_encrypted_archive(
            archive, key, tmp_path / "r", manifest_json=json_path, recipient_cert=cert)


def test_manifest_has_no_secrets_and_right_shape(tmp_path):
    components = [
        {"name": "secsso", "kind": "stack", "captured": ["authentik.sql", "users.generated.yaml", ".env"]},
        {"name": "seccert", "kind": "service", "captured": ["ca/", "seccert.db", "seccert.env"]},
    ]
    jp, tp = backup.write_backup_manifest(
        tmp_path, "fedora-fips", "core", suite={"version": "1.7.0"}, components=components,
        archive_name="secsuite-fedora-fips-core-X.tar.cms", plaintext_sha256="a" * 64,
        archive_sha256="b" * 64, plaintext_bytes=1000, archive_bytes=1200,
        recipient_fingerprint="AA:BB", ts="20260807T120000Z", now=FIXED_NOW,
    )
    rec = json.loads(jp.read_text())
    assert rec["schema_version"] == backup.SCHEMA_VERSION
    assert rec["generated_at"] == FIXED_NOW.isoformat()
    assert rec["kind"] == "backup"
    assert rec["archive"]["cipher"] == "cms-aes-256-cbc"
    assert rec["archive"]["plaintext_sha256"] == "a" * 64
    assert [c["name"] for c in rec["components"]] == ["secsso", "seccert"]
    # the manifest names WHAT was captured (filenames) but never a secret VALUE
    blob = jp.read_text() + tp.read_text()
    assert "authentik.sql" in blob and ".env" in blob
    assert "PG_PASS" not in blob and "PASSWORD" not in blob and "PRIVATE KEY" not in blob
