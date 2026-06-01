"""`fusekit apply` command boundary."""

from __future__ import annotations

import argparse


def run(args: argparse.Namespace) -> int:
    """Apply a setup manifest through the shared provider orchestration."""

    from fusekit import cli as orchestration

    return orchestration._cmd_apply(args)
