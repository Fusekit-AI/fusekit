"""`fusekit launch` and `fusekit setup` command boundary."""

from __future__ import annotations

import argparse


def run(args: argparse.Namespace) -> int:
    """Run the one-click launch orchestration."""

    from fusekit import cli as orchestration

    return orchestration._cmd_setup(args)
