# OCI Hosted Launcher Deployment Templates

These files are non-secret templates for the permanent AMD/x86_64 OCI host that
serves `fusekit.snowmanai.org`.

They are intentionally narrow:

- both services bind to loopback and are expected to sit behind an HTTPS reverse
  proxy;
- the nginx reverse proxy exposes only public ports 80/443, proxies the hosted
  app to loopback `127.0.0.1:8080`, proxies worker dispatch under
  `/worker-dispatch/` to loopback `127.0.0.1:8766`, and expects origin TLS
  material at `/etc/fusekit/tls/fusekit-origin.crt` plus
  `/etc/fusekit/tls/fusekit-origin.key`;
- the host firewall helper inserts only a TCP 80/443 accept rule ahead of the
  OCI image default reject and persists it with `netfilter-persistent` or
  `/etc/iptables/rules.v4`;
- runtime secrets live only in `/etc/fusekit/hosted-secrets.env` with
  `root:root` ownership and `0600` permissions, inside a root-owned
  `/etc/fusekit` directory;
- non-secret release provenance lives in `/etc/fusekit/hosted-provenance.env`
  so release automation can update the public commit proof without reading or
  rewriting the secret runtime file;
- mutable persistent state is constrained to `/var/lib/fusekit` and
  `/var/log/fusekit`, while `/run/fusekit` is managed by systemd
  `RuntimeDirectory`;
- worker dispatch duplicate-click state lives in
  `/var/lib/fusekit/dispatch-state`, created by tmpfiles as a private
  non-symlink directory before `/readiness` can report production-ready worker
  dispatch;
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
sudo install -d -o root -g root -m 0755 /etc/fusekit/tls
sudo install -o root -g root -m 0644 fusekit-origin.crt \
  /etc/fusekit/tls/fusekit-origin.crt
sudo install -o root -g root -m 0600 fusekit-origin.key \
  /etc/fusekit/tls/fusekit-origin.key
sudo install -o root -g root -m 0644 deploy/oci/nginx/fusekit-hosted.conf \
  /etc/nginx/sites-available/fusekit-hosted
sudo ln -sfn /etc/nginx/sites-available/fusekit-hosted \
  /etc/nginx/sites-enabled/fusekit-hosted
sudo deploy/oci/firewall/fusekit-hosted-firewall.sh
sudo nginx -t
sudo systemctl restart nginx
sudo EXPECTED_COMMIT_SHA="$(git rev-parse HEAD)" \
  deploy/oci/release/fusekit-hosted-release.sh
```

The release script prints the release receipt path. The nginx TLS key and
runtime secret file are host-only secrets and must not be pasted into docs,
logs, receipts, or public artifacts. Attach the release receipt to the host
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
sudo -E fusekit-hosted-runtime-secret-plan \
  --allow-generated-state-secrets \
  --execute \
  > hosted-runtime-secret-install.json
sudo fusekit-hosted-runtime-secret-plan \
  --verify-file /etc/fusekit/hosted-secrets.env \
  > hosted-runtime-secret-verify.json
fusekit-hosted-oci-replacement-plan \
  --inventory-report hosted-oci-inventory.json \
  --runtime-secret-report hosted-runtime-secret-verify.json \
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
runtime secret verify receipt is missing, incomplete, or only an install/dry-run
receipt.
`fusekit-hosted-runtime-secret-plan` dry-runs by default, and writes
`/etc/fusekit/hosted-secrets.env` only with `--execute`. After writing, run it
again with `--verify-file /etc/fusekit/hosted-secrets.env`; that verify receipt
must prove the file is private, regular, not a symlink, has the required hosted
env names, keeps managed runs disabled, and can stage the verified Stripe Price
without emitting the live Stripe secret, GitHub App private key, hosted state
secret, worker secret, OCI credentials, or vault material.

Keep paid managed runs disabled until the redacted enablement bundle is complete:
hosted verifier, runtime-secret verifier, Stripe Price verifier, Stripe webhook
verifier, public hosted readiness with writable job-store proof, and live
managed Checkout proof that includes paid Checkout, webhook application, and
worker-dispatch acceptance. Build that last proof with
`fusekit-hosted-live-checkout-proof --job-id <job-id>` so the command reads the
hash-wrapped redacted webhook and managed-start artifacts from
`/var/lib/fusekit/hosted-jobs`. Then run `fusekit-hosted-managed-enable` as a
dry run first, and only rerun it with `--execute --confirm-managed-enablement`
if the report says `ready_to_enable: true`.

While `FUSEKIT_MANAGED_RUNS_ENABLED=0`, the public managed lane stays
non-launchable. To collect the one supervised live proof run without opening the
lane to everyone, create a proof-purpose GitHub `state` token on the VM:

```zsh
sudo fusekit-hosted-managed-proof-token \
  --runtime-secret-file /etc/fusekit/hosted-secrets.env \
  > /tmp/fusekit-managed-proof-token.json
```

The helper refuses to emit a state token unless runtime secrets, Stripe webhook
proof staging, public hosted readiness, the writable hosted job store, the BYO
lane, and the managed-disabled state all pass. Use the returned `install_url`, or
its `state` query value, for that proof run. Do not put the state token in run
records or durable receipts; it is a temporary click capability, not a provider
credential.

For durable OCI posture evidence, write the same preflight without the temporary
click token:

```zsh
sudo fusekit-hosted-managed-proof-token \
  --runtime-secret-file /etc/fusekit/hosted-secrets.env \
  --redacted \
  > /var/lib/fusekit/posture/managed-proof-preflight.json
sudo fusekit-oci-host-posture --collect \
  --managed-proof-preflight-report /var/lib/fusekit/posture/managed-proof-preflight.json \
  ...
```
