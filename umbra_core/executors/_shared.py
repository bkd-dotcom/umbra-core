"""Shared, side-effect-free helpers for executor adapters."""
from __future__ import annotations

import os
import subprocess
from pathlib import Path
from typing import Callable

Runner = Callable[..., "subprocess.CompletedProcess[str]"]


def git(repo_path: Path, args: list[str]) -> str:
    """Run a read-only git command in the checkout and return stdout.

    ``core.quotePath=false`` so non-ASCII filenames arrive unquoted/unescaped —
    otherwise git wraps them in quotes with octal escapes, which no contract glob
    would match (a scope-bypass vector)."""
    result = subprocess.run(
        ["git", "-c", "core.quotePath=false", *args],
        cwd=repo_path, text=True, capture_output=True, check=False,
    )
    return result.stdout


def changed_files(repo_path: Path) -> list[str]:
    return [line for line in git(repo_path, ["diff", "--name-only"]).splitlines() if line]


def unified_diff(repo_path: Path) -> str:
    return git(repo_path, ["diff", "--binary"])


def sanitize_paths(text: str, repo_path: Path) -> str:
    """Strip the disposable checkout's absolute path out of agent prose.

    Agents freely embed the absolute temp-dir path in explanations; left raw it
    leaks the host filesystem layout into user-facing reports. The git diff
    already uses repo-relative ``a/…``/``b/…`` prefixes, so only free text needs
    this.
    """
    if not text:
        return text
    prefixes: set[str] = set()
    for base in (str(repo_path), str(repo_path.resolve())):
        prefixes.add(base)
        if base.startswith("/private/"):
            prefixes.add(base[len("/private"):])
        elif base.startswith("/var/"):
            prefixes.add("/private" + base)
    for prefix in sorted(prefixes, key=len, reverse=True):
        text = text.replace(prefix + os.sep, "").replace(prefix, "")
    return text


def bounded_prompt(mission: str, agent_label: str) -> str:
    """The hard no-authority instruction wrapped around every mission."""
    return f"""You are {agent_label} working for Umbra in a disposable local checkout.
Mission: {mission}

Hard rules: never push, commit, create a PR, merge, approve, deploy, force-push,
or expose a secret. You may inspect and edit only this checkout. Make the minimum
safe change, run relevant tests, and finish with a concise explanation of changed
files, exact tests run, and anything that prevented verification."""


def reason_prompt(mission: str, agent_label: str) -> str:
    return f"""You are {agent_label} acting as Umbra's reasoning analyst in a read-only workspace.
Task:
{mission}

Rules: Do not edit, create, run, push, or inspect any files. Reason only from the
text supplied above. Never invent files, line numbers, commit SHAs, CVEs, or
behavior. If context is insufficient, say so plainly. Respond with a concise,
well-structured analysis and nothing else."""
