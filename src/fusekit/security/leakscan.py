"""Secret-leak scanning for repos and FuseKit artifacts."""

from __future__ import annotations

import re
from dataclasses import dataclass
from pathlib import Path

SECRET_PATTERNS = (
    re.compile(r"sk-[A-Za-z0-9_\-]{16,}"),
    re.compile(r"gh[pousr]_[A-Za-z0-9_]{20,}"),
    re.compile(r"-----BEGIN (?:RSA |OPENSSH |EC |)PRIVATE KEY-----"),
    re.compile(r"(?i)(api[_-]?key|secret|token|password)\s*[:=]\s*['\"]?[^'\"\s]{8,}"),
)

EXCLUDED_PARTS = {
    ".git",
    ".venv",
    ".next",
    "node_modules",
    "__pycache__",
    "build",
    "dist",
    ".pytest_cache",
    ".ruff_cache",
    ".mypy_cache",
}

EXCLUDED_SUFFIXES = {
    ".png",
    ".jpg",
    ".jpeg",
    ".gif",
    ".webp",
    ".ico",
    ".pdf",
    ".zip",
    ".gz",
    ".tar",
}


@dataclass(frozen=True)
class LeakFinding:
    """One non-secret leak finding."""

    path: str
    line: int
    kind: str

    def to_dict(self) -> dict[str, str | int]:
        """Serialize the finding."""

        return {"path": self.path, "line": self.line, "kind": self.kind}


def scan_for_secret_leaks(root: Path) -> list[LeakFinding]:
    """Scan a tree for secret-looking plaintext without returning secret values."""

    findings: list[LeakFinding] = []
    for path in root.rglob("*"):
        if not path.is_file() or _excluded(path):
            continue
        try:
            text = path.read_text(encoding="utf-8")
        except UnicodeDecodeError:
            continue
        except OSError:
            continue
        for index, line in enumerate(text.splitlines(), start=1):
            for pattern in SECRET_PATTERNS:
                if pattern.search(line):
                    findings.append(
                        LeakFinding(
                            path=str(path.relative_to(root)),
                            line=index,
                            kind=_kind_for_pattern(pattern),
                        )
                    )
                    break
    return findings


def _excluded(path: Path) -> bool:
    if any(part in EXCLUDED_PARTS for part in path.parts):
        return True
    if path.suffix.lower() in EXCLUDED_SUFFIXES:
        return True
    if path.name.endswith((".vault", ".vault.json")):
        return True
    return False


def _kind_for_pattern(pattern: re.Pattern[str]) -> str:
    source = pattern.pattern.lower()
    if "private key" in source:
        return "private_key"
    if "gh" in source:
        return "github_token"
    if "sk-" in source:
        return "api_key"
    return "secret_assignment"
