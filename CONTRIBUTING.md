# Contributing to Project Veil

Thanks for helping. Project Veil is proprietary (see [LICENSE](LICENSE)), so please read
step 1 before writing any code.

## 1. Sign the contributor agreement first

Read [`CONTRIBUTOR-AGREEMENT.md`](CONTRIBUTOR-AGREEMENT.md), fill in the signing block, and send
the signed copy to the owner **privately** (not in an issue or a pull request: it has personal
details). It lets you work on the code for contributions, and lets the owner use what you submit.
The owner counter-signs and confirms before your first pull request is reviewed.

## 2. Fork, branch, pull request

1. Fork `AryanilPanja/Project-Veil` on GitHub and clone your fork.
2. Create a branch per task, named `<area>/<short-task>` (e.g. `macos/t1-ci`).
3. Commit with your **GitHub noreply address** as the author email
   (`git config user.email <id>+<user>@users.noreply.github.com`).
4. Open a pull request **into `main`** of `AryanilPanja/Project-Veil`. Keep each one to a single
   task; small pull requests get reviewed faster.
5. CI (lint + tests) must pass, and the owner must approve. On your first pull request, CI waits
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
