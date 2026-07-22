<!-- Thanks for contributing! Please keep the core deterministic and honest. -->

## What & why

<!-- What does this change and why? Link any issue. -->

## Checklist

- [ ] Tests added/updated and `uv run pytest` passes
- [ ] `uv run ruff check .` passes
- [ ] No model/network calls added to the deterministic pipeline (agent/LLM work stays behind the `Executor` protocol or the optional classifier hook)
- [ ] Core invariants preserved (`auto_merge` always false; authority earned from evidence; verifier never fabricates a pass; receipts verify against a pinned key)
- [ ] Output/docs stay honest (enforcement tiers, model provenance, detection scope not overstated)
- [ ] If security-relevant, I've noted the impact and threat-model implications

## Notes for reviewers

<!-- Anything to look at closely, or invariants this intentionally touches. -->
