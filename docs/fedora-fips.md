# FIPS-ready Fedora runbook

The production target: native, hardened **systemd** services on a Fedora host running in FIPS
mode. No containers — each component links the host's OpenSSL FIPS provider directly, the
tightest crypto boundary. SecDeploy refuses to deploy (fail-closed) if the host isn't FIPS-ready.

## 1. Put the host in FIPS mode

```bash
sudo fips-mode-setup --enable
sudo reboot
# after reboot, confirm:
cat /proc/sys/crypto/fips_enabled        # → 1
fips-mode-setup --check                  # → "FIPS mode is enabled."
openssl list -providers | grep -i fips   # → fips provider present
```

## 2. Runtimes

```bash
sudo dnf install -y nodejs git           # Node >= 24 for SecRouter
# uv for the Python components (SecCert, SecRecorder):
curl -LsSf https://astral.sh/uv/install.sh | sh
```

## 3. Deploy

```bash
# Always preview the exact runbook first:
sudo uv run secdeploy deploy fedora-fips --dry-run

# Then run it (as root — installs users, code, systemd units, trust anchor):
sudo uv run secdeploy deploy fedora-fips
```

`deploy fedora-fips` performs, in order:
1. **FIPS preflight** (`deploy/fedora-fips/fips-preflight.sh`) — fail-closed.
2. Create system users `secsuite-{seccert,secrouter,secrecorder}` and owner-only state dirs.
3. Build natively from the pinned checkouts (SecRouter `npm run build`; SecCert/SecRecorder `uv sync`).
4. Install code to `/opt/secsuite`, config to `/etc/secsuite/*.env`.
5. Install hardened systemd units + `secsuite.target`; `daemon-reload`.
6. `systemctl enable --now secsuite.target` (SecCert → SecRouter → SecRecorder).
7. Add the SecCert root to the host trust store (`update-ca-trust`).

## 4. Configure

Edit the env files the installer dropped (they don't overwrite existing ones):

```bash
sudoedit /etc/secsuite/seccert.env      # set SECCERT_ADMIN_TOKEN, SECCERT_CA_PASSPHRASE, external URL
sudoedit /etc/secsuite/secrouter.env    # point FREEROUTER_CONFIG at a hardened config
sudoedit /etc/secsuite/secrecorder.env  # or: sudo systemctl mask secrecorder.service to skip it
sudo systemctl restart secsuite.target
```

SecRouter's config must enable the security block and `tls.mode: frontend|native`; it fails
closed if FIPS is required but unavailable. Start from `freerouter.config.hardened.example.json`
in the SecRouter checkout.

## 5. Operate

```bash
uv run secdeploy status fedora-fips
systemctl status secsuite.target
journalctl -u secrouter.service -f
sudo systemctl restart seccert.service
```

## Hardening applied

The units set `NoNewPrivileges`, `ProtectSystem=strict`, `ProtectHome`, `PrivateTmp`,
`ProtectKernel*`, `RestrictAddressFamilies`, `RestrictNamespaces`, `LockPersonality`, and
per-service `ReadWritePaths` scoped to `/var/lib/secsuite/<svc>`. Review and tighten further
for your accreditation boundary.
