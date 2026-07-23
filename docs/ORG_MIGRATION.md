# Migrating the Umbra repos into a GitHub Organization

Status: **planned** — execute *after* the Claude Code plugin community-marketplace
review resolves, so the pending submission (pinned to `bkd-dotcom/umbra-plugins`)
isn't disrupted mid-review.

## Why the ordering matters

Three things are pinned to the `bkd-dotcom` account and **break or need re-linking**
on transfer. Do them in this order to avoid downtime:

| Coupling | What breaks on transfer | Fix |
|---|---|---|
| **PyPI Trusted Publisher** (`umbra-core`) | OIDC publish fails — the `release.yml` job can't publish | Re-register a pending/real publisher under `<ORG>/umbra-core`, workflow `release.yml`, env `pypi` |
| **GitHub Marketplace** (`umbra-action`) | Listing may unpublish/relink | Re-verify the Marketplace listing points at `<ORG>/umbra-action` after transfer |
| **Claude Code plugin review** (`umbra-plugins`) | Pending submission references the old path | Only transfer once the review has resolved; update `marketplace.json` links |

GitHub **auto-redirects** old repo URLs (clones, links, `uses:` refs) after a
transfer, so external consumers keep working — but the three items above are not
covered by that redirect.

## Prerequisites

- The org exists (create at <https://github.com/organizations/plan>, Free plan).
- `gh` has `admin:org` + `repo` scope: `gh auth refresh -h github.com -s admin:org,repo`
- The plugin marketplace review has resolved.

## Transfer (run these once ORG is set)

```bash
ORG="<your-org>"     # e.g. umbra-sec
for r in umbra-core umbra-action umbra-plugins umbra-demo-repo; do
  gh api -X POST "repos/bkd-dotcom/$r/transfer" -f "new_owner=$ORG"
done
```

## Post-transfer fixes (all scripted/checked by hand)

1. **PyPI publisher** — at <https://pypi.org/manage/project/umbra-core/settings/publishing/>
   add a Trusted Publisher: owner `<ORG>`, repo `umbra-core`, workflow `release.yml`,
   environment `pypi`. Remove the old `bkd-dotcom` publisher.
2. **Branch protection** — re-apply on `<ORG>/umbra-core` `main`
   (`.github` protection JSON) and enable `enforce_admins`.
3. **CODEOWNERS** — change `@bkd-dotcom` → `@<ORG>/maintainers` (after creating a
   `maintainers` team) in both repos.
4. **Cross-repo links** — update `bkd-dotcom/…` → `<ORG>/…` in:
   READMEs, `docs/site/*`, `integrations/github-action/example-workflow.yml`,
   `umbra-action` README/`action.yml` comments, `umbra-plugins`
   `.claude-plugin/marketplace.json`, `docs/INTEGRATIONS.md`, `docs/LAUNCH.md`.
5. **Action pin** — `uses: bkd-dotcom/umbra-action@v1` → `uses: <ORG>/umbra-action@v1`
   (the redirect keeps the old one working, but update docs for correctness).
6. **Docs site** — GitHub Pages / custom domain on `<ORG>/umbra-core`.
7. **Marketplace** — confirm the `umbra-action` listing shows the new owner.
8. **Re-run a release** — tag a patch (e.g. `v0.2.2`) to confirm PyPI publish +
   GitHub Release automation work under the org.

## Teams to create in the org

- `maintainers` — write access to all repos; used by `CODEOWNERS`.
- (optional) `security` — for triaging advisories.
