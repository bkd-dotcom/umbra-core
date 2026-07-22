# Quickstart

## Install

```bash
pip install umbra-core          # or: uv pip install umbra-core
```

## Govern a change from Python

```python
from pathlib import Path
from umbra_core import get_executor, run_admission, build_receipt, verify_receipt, public_key_b64

agent = get_executor("claude-code")          # or "codex-cli", or "none" for an existing diff
report = run_admission(
    repo_path=Path("checkout"),
    repo_label="acme/app",
    mission="update the vulnerable dependency; change only manifests",
    executor=agent,
)
print(report.authority_level, report.authority)   # e.g. 2 branch_pr
print(report.outcome)

envelope = build_receipt(
    repo=report.repo, base_commit=report.base_commit, contract=report.contract,
    contract_result=report.contract_result, verifier=report.verifier,
    trust_boundary=report.trust_boundary, proposed_change=report.proposed_change,
    providers=report.providers, authority_level=report.authority_level,
    authority=report.authority, executor=report.executor, diff=report.diff,
    checks=report.checks, model_identity=report.model_identity, outcome=report.outcome,
)
# Verify against a PINNED key. In production set UMBRA_SIGNING_KEY and pin the
# published key; the dev-fallback key is refused unless pinned explicitly.
assert verify_receipt(envelope, expected_public_key=public_key_b64())["verified"]
```

## Govern from the CLI

```bash
umbra admit . --agent none --mission "review the pending change" --min-authority 1
umbra verify receipt.json --public-key <base64-pubkey>
umbra provenance receipt.json      # in-toto / SLSA statement
umbra brake acme app --store passports.json --reason "incident-42"
```

`umbra admit` exits non-zero unless the change earns at least `--min-authority`,
so it gates a git pre-push hook or CI.

## Declare a contract

Add `.umbra/admission.yaml` to the repo:

```yaml
version: 1
allowed_paths:
  - "src/**"
  - "package.json"
forbidden_paths:
  - "**/deploy.y*ml"
  - ".github/workflows/**"
  - "**/.env*"
  - "**/*secret*"
max_files_changed: 10
required_checks:
  - "pytest"
policy_owner: platform-team
policy_version: "1.0"
```

Without one, a conservative default applies.
