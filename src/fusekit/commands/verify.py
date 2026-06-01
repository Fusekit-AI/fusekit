"""`fusekit verify` command."""

from __future__ import annotations

import argparse
import json

from fusekit.providers.vercel import verify_live_url


def run(args: argparse.Namespace) -> int:
    """Verify a live app URL."""

    result = verify_live_url(args.url)
    print(json.dumps(result, indent=2, sort_keys=True))
    return 0 if result["ok"] else 1
