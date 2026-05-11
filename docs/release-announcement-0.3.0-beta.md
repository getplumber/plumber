# Plumber v0.3.0-beta — GitHub Actions support


---

## TL;DR

Plumber now scans GitHub Actions workflows with the same engine, same `.plumber.yaml`, and same CLI you already use for GitLab. **Your existing GitLab usage is unchanged** — same flags, same output, same exit codes. The only thing you'll notice if you stay on GitLab is a one-line deprecation warning suggesting you upgrade the `.plumber.yaml` schema (optional).

If you want to scan a GitHub Actions project too, this release lets you.

---

## 1. Install

Beta is not on Homebrew. Pick a direct download for your platform:

```bash
# macOS (Apple Silicon)
curl -LO https://github.com/getplumber/plumber/releases/download/v0.3.0-beta/plumber-darwin-arm64
chmod +x plumber-darwin-arm64 && sudo mv plumber-darwin-arm64 /usr/local/bin/plumber

# macOS (Intel)
curl -LO https://github.com/getplumber/plumber/releases/download/v0.3.0-beta/plumber-darwin-amd64
chmod +x plumber-darwin-amd64 && sudo mv plumber-darwin-amd64 /usr/local/bin/plumber

# Linux (amd64)
curl -LO https://github.com/getplumber/plumber/releases/download/v0.3.0-beta/plumber-linux-amd64
chmod +x plumber-linux-amd64 && sudo mv plumber-linux-amd64 /usr/local/bin/plumber

# Linux (arm64)
curl -LO https://github.com/getplumber/plumber/releases/download/v0.3.0-beta/plumber-linux-arm64
chmod +x plumber-linux-arm64 && sudo mv plumber-linux-arm64 /usr/local/bin/plumber

# Docker
docker pull getplumber/plumber:0.3.0-beta
```

Verify:

```bash
plumber version       # expect: v0.3.0-beta
```

---

## 2. Pick your test track

Three independent scenarios. Run whichever apply to you — you don't have to do all three.

| Track | Who it's for | Time |
|---|---|---|
| **A. GitLab regression** | You already use Plumber for GitLab and want to confirm nothing broke | 5 min |
| **B. First GitHub scan** | You have a GitHub Actions project (clone or remote) | 10 min |
| **C. Upstream-fetch** | You want to scan a GitHub repo without cloning it (security-team workflow) | 5 min |

---

### Track A — GitLab regression

```bash
cd ~/path/to/your/gitlab/project
export GITLAB_TOKEN=glpat-…
plumber analyze
```

**Expected:** identical output to your previous Plumber run, with one new line:

```
WARN: legacy config schema detected; run 'plumber config migrate' to upgrade.
      v1 support will be removed in 1.0.0.
```

That warning is the only change. If anything else is different, please report it.

#### Optional: upgrade your `.plumber.yaml` schema

Plumber moved from a single root-level `controls:` block (v1) to per-provider sections (v2). Today your file looks like this:

```yaml
controls:
  containerImageMustNotUseForbiddenTags: { ... }
  branchMustBeProtected: { ... }
```

The new shape moves your controls one indent deeper under `gitlab:`, and reserves a parallel `github:` section for when you want it:

```yaml
version: "2.0"
gitlab:
  controls:
    containerImageMustNotUseForbiddenTags: { ... }
    branchMustBeProtected: { ... }
```

You don't have to upgrade — Plumber auto-converts v1 in memory on every run. But if you want to clean it up:

```bash
plumber config migrate              # writes .plumber.yaml.v2 alongside the original
# review, then either rename or:
plumber config migrate --in-place   # overwrites .plumber.yaml; backs up to .plumber.yaml.bak
```

Comments are preserved. The migration is idempotent (safe to re-run).

---

### Track B — First GitHub scan

You'll need:
1. A checked-out GitHub repo with workflows under `.github/workflows/`
2. A GitHub-aware `.plumber.yaml`
3. (Recommended) GitHub auth

#### Step 1: Get a GitHub-aware `.plumber.yaml`

Two ways. Pick the one that fits.

**Option 1 — interactive wizard** (best if you want to be walked through it):

```bash
cd ~/path/to/your/github/project
plumber config init -o .plumber.yaml
```

The wizard auto-detects GitHub from your git remote and pre-checks the right provider on the first question. It walks you through the GitHub-specific controls: third-party action SHA pinning, dangerous triggers, workflow permissions, security-job patterns, branch protection, etc.

**Option 2 — generate the full commented template, then trim** (best if you want a reference of everything available):

```bash
plumber config generate -o .plumber.yaml --force
```

This writes the official template with both `gitlab:` and `github:` sections fully populated and commented. Keep both sections if your team works in both ecosystems, or delete the one you don't need.

#### Step 2: Authenticate (recommended)

```bash
gh auth login                        # easiest, uses your gh CLI credential
# OR
export GH_TOKEN=ghp_…                # personal access token
```

Local-clone analysis works without auth but the repo-level controls (branch protection) silently abstain — the postflight output flags that case clearly.

#### Step 3: Run

```bash
plumber analyze --output report.json --pbom pbom.json --pbom-cyclonedx sbom.json
```

**Expected:** per-control compliance percentages for the 9 GitHub controls (SHA pinning, dangerous triggers, permissions, template injection, reusable-workflow secrets, security-job weakening, container images, DinD, branch protection). Three artifacts on disk: `report.json` (per-control results), `pbom.json` (container images + every `uses: owner/repo@<sha>` action reference), `sbom.json` (CycloneDX 1.5 — ingestible by Grype / Trivy / Dependency-Track).

---

### Track C — Scan a GitHub repo without cloning it

Symmetric to GitLab's `--gitlab-url + --project` flow:

```bash
gh auth login        # auth is required in this mode
plumber analyze --github-url github.com --project getplumber/plumber --output report.json
```

Same per-control output as Track B, no local clone needed. Works on GitHub Enterprise Server too — pass the GHES host instead of `github.com`.

---

## 3. Token scope note (GitHub branch protection)

For `branchMustBeProtected` to evaluate the full rule set (force-push + code-owner-approval), the token needs **`Administration: Read`** (fine-grained PAT) or **`repo`** scope (classic PAT). Without it, the rule silently abstains and a `partialControls` block in the JSON output makes the abstention explicit — no false 100% claims. `gh auth login` with a user account that has admin on the repo works without any extra scope work.

---

## 4. What I'm looking for

- **GitLab regression**: anything that worked before but doesn't now.
- **GitHub findings sanity**: do the 9 controls report things you'd expect for your repo? Anything noisy or obviously wrong?
- **Wizard UX**: was `plumber config init` clear? Anything confusing or missing?
- **CLI ergonomics**: any flag or message that felt unfamiliar coming from the GitLab-only flow?
- **Output artifacts**: `report.json` / `pbom.json` / `sbom.json` — does the shape match what you'd want to script against?

Reply with findings or open an issue at https://github.com/getplumber/plumber/issues. Screenshots welcome. Thanks for stress-testing! 🛠
