# OCI Hosted Launcher Deployment Templates

These files are non-secret templates for the permanent AMD/x86_64 OCI host that
serves `fusekit.snowmanai.org`.

They are intentionally narrow:

- both services bind to loopback and are expected to sit behind an HTTPS reverse
  proxy;
- runtime secrets live only in `/etc/fusekit/hosted-secrets.env` with
  `root:root` ownership and `0600` permissions, inside a root-owned
  `/etc/fusekit` directory;
- non-secret release provenance lives in `/etc/fusekit/hosted-provenance.env`
  so release automation can update the public commit proof without reading or
  rewriting the secret runtime file;
- mutable state is constrained to `/var/lib/fusekit`, `/var/log/fusekit`, and
  `/run/fusekit`;
- the units use the `fusekit` system user with `NoNewPrivileges`, `PrivateTmp`,
  `ProtectSystem`, home/device/kernel/control-group protections, no ambient or
  bounding capabilities, restricted address families, owner-only umask,
  systemd-managed state/log/runtime directories, and a constrained writable
  path set.

The release script is intentionally narrow and reviewable. It accepts one exact
40-character commit SHA, clones only `https://github.com/Fusekit-AI/fusekit.git`,
installs into `/opt/fusekit/releases/<commit>`, moves only the
`/opt/fusekit/current` symlink, writes only the non-secret provenance file,
restarts only `fusekit-hosted.service` and `fusekit-worker-dispatch.service`,
and emits a redacted release receipt under `/var/lib/fusekit/release-receipts`.

```zsh
sudo EXPECTED_COMMIT_SHA="$(git rev-parse HEAD)" \
  deploy/oci/release/fusekit-hosted-release.sh
```

The script prints the release receipt path. Attach that receipt to the host
posture collector after the outside-in verifier succeeds, for example
`/var/lib/fusekit/release-receipts/release-<commit>.json`.

After installing the units, collect and validate redacted host evidence:

```zsh
fusekit-hosted-verify \
  --origin https://fusekit.snowmanai.org \
  --expected-commit-sha "$(git rev-parse HEAD)" \
  > hosted-verify.json
fusekit-hosted-oci-access-plan \
  --instance-json instance.json \
  --vnic-json vnic.json \
  --plugins-json plugins.json \
  --hosted-verify-report hosted-verify.json \
  --ssh-probe-status permission_denied \
  --expected-commit-sha "$(git rev-parse HEAD)" \
  > oci-access-plan.json
fusekit-hosted-oci-inventory \
  --hosted-verify-report hosted-verify.json \
  --ssh-probe-status permission_denied \
  --expected-commit-sha "$(git rev-parse HEAD)" \
  > hosted-oci-inventory.json
fusekit-hosted-runtime-secret-plan \
  --allow-generated-state-secrets \
  > hosted-runtime-secret-plan.json
fusekit-hosted-oci-replacement-plan \
  --inventory-report hosted-oci-inventory.json \
  --runtime-secret-report hosted-runtime-secret-plan.json \
  --replacement-shape VM.Standard.E5.Flex \
  --replacement-os 'Canonical Ubuntu' \
  --replacement-os-version 24.04 \
  --replacement-run-command-availability available_not_installed \
  --expected-commit-sha "$(git rev-parse HEAD)" \
  > hosted-oci-replacement-plan.json
fusekit-oci-host-posture --collect \
  --shape VM.Standard.E5.Flex \
  --ssh-ingress restricted \
  --hosted-verify-report hosted-verify.json \
  --dns-report dns-propagation.json \
  --release-receipt /var/lib/fusekit/release-receipts/release-"$(git rev-parse HEAD)".json \
  --rollback-metadata rollback_plan.json \
  --cis-summary cis-summary.json \
  --rootkit-summary rootkit-summary.json \
  --output posture.json
fusekit-oci-host-posture --evidence posture.json
```

The DNS, release receipt, and rollback files must be redacted public proof. The
posture validator only needs to see that `fusekit.snowmanai.org` has propagated,
that the release receipt commit matches the hosted verifier commit, and that
provider rollback actions are planned or complete; it must not receive provider
tokens, private keys, vault material, or raw setup logs.

If the current image cannot support OCI Run Command and SSH release access is
not ready, use `fusekit-hosted-oci-replacement-plan` before requesting any host
replacement. The plan is non-mutating: it requires an AMD/x86_64 shape, supported
Ubuntu image, a replacement deploy path through Run Command or approved SSH, and
keeps the old host plus Cloudflare DNS unchanged until replacement verifier,
posture, release receipt, DNS dry-run, and rollback proof all pass. It also
forbids MailPilot/AWS, Stripe, generated-app/provider credentials, tenancy-wide
policy broadening, and ARM/Ampere shapes in the repair path.

The replacement plan distinguishes replacement infrastructure from cutover. A
candidate host can be ready to create while `ready_for_dns_cutover=false` if the
runtime secret plan is missing or incomplete. `fusekit-hosted-runtime-secret-plan`
must prove the required hosted env names are available for
`/etc/fusekit/hosted-secrets.env`, that managed runs remain disabled, and that
the verified Stripe Price can be staged without emitting the live Stripe secret,
GitHub App private key, hosted state secret, worker secret, OCI credentials, or
vault material.
