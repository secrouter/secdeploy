# Releasing the suite

A **suite release** is a single tested combination of component versions, captured in
[`suite.toml`](../suite.toml). It decouples the suite's own version from each component's
version — the whole point of a bill of materials.

## The manifest

```toml
suite = "1.0.0"
released = "2026-07-30"

[components.seccert]
repo = "secrouter/seccert"
ref  = "v1.0.0"          # the pinned, compatible tag

[components.secrouter]
repo = "secrouter/secrouter"
ref  = "v1.0.0"

[components.secrecorder]
repo = "secrouter/secrecorder"
ref  = "v0.7.0"          # components move at their own pace
```

`ref` may be a tag (preferred for releases), a branch, or a commit SHA.

## Cutting a new suite version

1. Tag each component at the version you want to ship, e.g.:
   ```bash
   git -C ../seccert tag -a v1.0.0 -m "SecCert v1.0.0" && git -C ../seccert push origin v1.0.0
   ```
2. Update `suite.toml`: bump `suite`, set `released`, and pin each component's `ref` to its tag.
3. `secdeploy verify` — confirm the manifest is valid and target assets are present.
4. `secdeploy fetch` then `secdeploy build <target>` on a connected host to prove the
   combination builds.
5. Tag SecDeploy itself (`git tag -a v1.0.0`) and, for air-gapped consumers,
   `secdeploy bundle <target>` and publish the tarball + `.sha256`.

## Compatibility policy

- The suite version is **SemVer** for the *bundle contract* (targets, manifest schema, CLI),
  not the sum of component versions.
- A suite patch may only bump component patch/minor refs that are backward compatible.
- Record any cross-component constraints (e.g. "SecRouter ≥ X needs SecCert ≥ Y") as a comment
  in `suite.toml` next to the affected component.
