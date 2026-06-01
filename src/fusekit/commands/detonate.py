"""`fusekit detonate` command."""

from __future__ import annotations

import argparse
import json

from fusekit.detonation.cleanup import detonate as detonate_paths


def run(args: argparse.Namespace) -> int:
    """Remove plaintext worker state while preserving requested artifacts."""

    removed = detonate_paths(args.paths, preserve=args.preserve)
    print(json.dumps({"detonated": removed}, indent=2, sort_keys=True))
    return 0
