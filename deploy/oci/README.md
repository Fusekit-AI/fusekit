# OCI Hosted Launcher Deployment Templates

These files are non-secret templates for the permanent AMD/x86_64 OCI host that
serves `fusekit.snowmanai.org`.

They are intentionally narrow:

- both services bind to loopback and are expected to sit behind an HTTPS reverse
  proxy;
- runtime secrets live only in `/etc/fusekit/hosted-secrets.env` with
  `root:root` ownership and `0600` permissions, inside a root-owned
  `/etc/fusekit` directory;
- mutable state is constrained to `/var/lib/fusekit`, `/var/log/fusekit`, and
  `/run/fusekit`;
- the units use the `fusekit` system user with `NoNewPrivileges`, `PrivateTmp`,
  `ProtectSystem`, home/device/kernel/control-group protections, no ambient or
  bounding capabilities, restricted address families, owner-only umask,
  systemd-managed state/log/runtime directories, and a constrained writable
  path set.

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
fusekit-oci-host-posture --collect \
  --shape VM.Standard.E5.Flex \
  --ssh-ingress restricted \
  --hosted-verify-report hosted-verify.json \
  --dns-report dns-propagation.json \
  --rollback-metadata rollback_plan.json \
  --cis-summary cis-summary.json \
  --rootkit-summary rootkit-summary.json \
  --output posture.json
fusekit-oci-host-posture --evidence posture.json
```

The DNS and rollback files must be redacted public proof. The posture validator
only needs to see that `fusekit.snowmanai.org` has propagated and that provider
rollback actions are planned or complete; it must not receive provider tokens,
private keys, vault material, or raw setup logs.
