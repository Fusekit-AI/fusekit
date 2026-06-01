"""`fusekit authorize` command boundary."""

from __future__ import annotations

import argparse


def run(args: argparse.Namespace) -> int:
    """Authorize a provider through the shared setup orchestration."""

    from fusekit import cli as orchestration

    return orchestration._cmd_authorize(args)
