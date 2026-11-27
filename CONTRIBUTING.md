# Contributing to Project Veil

Thanks for helping. Project Veil is licensed under the **GNU GPL version 3** with an
attribution term (see [LICENSE](LICENSE) and [NOTICE](NOTICE)).

## 1. Sign off your commits (DCO)

By contributing, you agree that your contribution is licensed under the same terms (GPL-3.0 with
the NOTICE attribution term), and you certify the
[Developer Certificate of Origin 1.1](https://developercertificate.org/): you wrote it, or have
the right to submit it under this license. Show that by signing off **every commit**:

```bash
git commit -s -m "..."     # adds: Signed-off-by: Your Name <your-noreply-email>
```

CI checks every commit in a pull request for that line. Forgot one? `git rebase --signoff main`,
then force-push your branch.

## 2. Fork, branch, pull request

Pick a task from [ROADMAP.md](ROADMAP.md) (each one is a GitHub issue) and comment on its issue to claim
it before you start.


1. Fork `AryanilPanja/Project-Veil` on GitHub and clone your fork.
2. Create a branch per task, named `<area>/<short-task>` (e.g. `macos/t1-ci`).
3. Commit (signed off) with your **GitHub noreply address** as the author email
   (`git config user.email <id>+<user>@users.noreply.github.com`).
4. Open a pull request **into `main`** of `AryanilPanja/Project-Veil`. Keep each one to a single
   task; small pull requests get reviewed faster.
5. CI (lint, tests, sign-off) must pass, and the owner must approve. On your first pull request, CI waits
   until the owner allows it to run. The owner merges; please don't push to `main` (it's protected).

## 3. Setup and checks

Requires [uv](https://docs.astral.sh/uv/) (it installs Python 3.13 for you).

```bash
uv sync
uv run pytest -q                                      # the full suite (a few minutes)
uv run ruff check . && uv run ruff format --check .   # lint and format
```

Run both before you push. Every change comes with tests: the happy path, edge cases (Unicode and
Indic scripts, empty values, boundaries) and failure modes. Code in `src/veil/engine/` also needs
property tests (hypothesis).

## 4. Privacy rules (non-negotiable)

- **Never commit real personal data**: not in code, tests, fixtures, docs, logs or commit
  messages. Use the synthetic persona in `tests/fixtures/` (Jane Doe → Alex Smith).
- Your own `persona.yaml` (if you make one) is git-ignored; `persona.example.yaml` is the blank
  template.
- veil's output and logs show field paths, counts and fake-side text only, never real values.
  Keep it that way.
- **Fail closed:** on any error, veil clears the clipboard or refuses; it never lets real text
  through. Errors never switch veil off.

## 5. Design changes

Anything beyond a local fix (a new platform backend, a new dependency, a change in behaviour) is
discussed in an issue or the pull request description first: what, why, alternatives. The owner
records the decision. The project's internal design docs aren't in the repository; ask the owner
for the parts you need.

## Porting to macOS (current work)

Start with a `macos-latest` job in `.github/workflows/ci.yml`; its failures are the to-do list.
The platform-specific code is small and isolated: `paths.py` (a safe place for plaintext),
`crypto/keystore.py` (key storage, behind the `SecretBackend` protocol), `hardening.py`,
`clip/` (clipboard, notifications, the copy watcher), `killswitch.py` (the background service)
and `shortcuts.py` (hotkeys). Each of these needs a short design proposal before the code.

## Dependency audit

The `lint + tests (Python 3.13)` job exports the locked dependency set with
`uv export --frozen --no-hashes --no-emit-project` and scans it with a pinned `uvx pip-audit`.
A known vulnerability fails the job; the committed lockfile is the source of truth. Actions are
pinned to full commit SHAs, and Dependabot groups updates into one PR per ecosystem.

For a false positive, add `--ignore-vuln <ID>` to the pip-audit command in `.github/workflows/ci.yml`
with a comment linking the advisory and the date of the review. Re-check each exception at review
time; never ignore a vulnerability without that record.
