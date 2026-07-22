"""Small, self-contained deterministic helpers used across the pipeline.

Ported from Umbra's ``features.py`` / ``remediation.py`` and trimmed to what the
governance core needs. No model, no network.
"""
from __future__ import annotations

import re
from dataclasses import asdict, dataclass

# Credential signatures. We report kind + line only — never the secret value.
SECRET_PATTERNS: dict[str, re.Pattern[str]] = {
    "OpenAI API key": re.compile(r"\bsk-[A-Za-z0-9_-]{20,}\b"),
    "GitHub token": re.compile(r"\bgh[pousr]_[A-Za-z0-9]{20,}\b"),
    "AWS access key": re.compile(r"\bAKIA[0-9A-Z]{16}\b"),
    "Slack token": re.compile(r"\bxox[baprs]-[A-Za-z0-9-]{10,}\b"),
    "Private key block": re.compile(r"-----BEGIN (?:RSA |EC |OPENSSH |DSA )?PRIVATE KEY-----"),
}


@dataclass(frozen=True)
class SecretFinding:
    file: str
    line: int
    kind: str
    confidence: float


def scan_secrets(text: str, file: str = "unknown") -> list[dict[str, object]]:
    """Find likely credentials in ``text`` without retaining their values.

    Files whose name looks like a fixture/example/sample are skipped, so a
    documented placeholder key never trips the blocking secret check.
    """
    findings: list[dict[str, object]] = []
    if any(marker in file.lower() for marker in ("fixture", "example", ".sample")):
        return findings
    for line_number, line in enumerate((text or "").splitlines(), start=1):
        for kind, pattern in SECRET_PATTERNS.items():
            if pattern.search(line):
                findings.append(asdict(SecretFinding(file, line_number, kind, 0.92)))
    return findings


def version_key(version: str) -> tuple[int, ...]:
    """A comparable numeric tuple from a version string (e.g. ``1.2.3`` → (1,2,3)).

    Deterministic and dependency-free; used by the optional advisory-cleared
    verifier check to confirm a bumped manifest actually escapes a fixed version.
    """
    parts = re.findall(r"\d+", version or "")
    return tuple(int(p) for p in parts[:4]) if parts else (0,)
