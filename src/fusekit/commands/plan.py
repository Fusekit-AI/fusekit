"""`fusekit plan` command."""

from __future__ import annotations

import argparse
import json

from fusekit.manifest import load_manifest
from fusekit.planner import build_plan


def run(args: argparse.Namespace) -> int:
    """Print a setup plan from a manifest."""

    manifest = load_manifest(args.manifest)
    setup_plan = build_plan(manifest)
    if args.as_json:
        print(json.dumps(setup_plan.to_dict(), indent=2, sort_keys=True))
        return 0
    for action in setup_plan.actions:
        print(f"{action.kind:17} {action.id:28} {action.summary}")
    return 0
