"""FuseKit domain errors."""

from __future__ import annotations


class FuseKitError(Exception):
    """Base class for expected FuseKit failures."""


class ManifestError(FuseKitError):
    """Raised when a manifest cannot be parsed or validated."""


class VaultError(FuseKitError):
    """Raised when vault encryption, unlock, or record access fails."""


class PolicyError(FuseKitError):
    """Raised when a requested action is denied by policy."""


class ProviderError(FuseKitError):
    """Raised when a provider API call fails."""


class ApprovalRequired(FuseKitError):
    """Raised when a command needs explicit human approval before continuing."""
