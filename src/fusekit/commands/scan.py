"""`fusekit scan` command."""

from __future__ import annotations

import argparse

from fusekit.manifest import write_manifest
from fusekit.scanner import scan_repo


def run(args: argparse.Namespace) -> int:
    """Scan an app repo and write a setup manifest."""

    manifest = scan_repo(args.path)
    write_manifest(manifest, args.output)
    print(f"Wrote setup manifest: {args.output}")
    return 0
