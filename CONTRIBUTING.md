# Contributing

veil is licensed under GPL-3.0-only with an attribution term (see [LICENSE](LICENSE) and
[NOTICE](NOTICE)).

## Sign off your commits (DCO)

By contributing you agree that your contribution is licensed under the same terms, and you
certify the [Developer Certificate of Origin 1.1](https://developercertificate.org/): you wrote
it, or have the right to submit it under this license. Sign off every commit:

```bash
git commit -s -m "..."     # adds: Signed-off-by: Your Name <your-noreply-email>
```

CI checks every commit in a pull request for that line. Forgot one? `git rebase --signoff main`,
then force-push your branch.

## Set up

Requires [uv](https://docs.astral.sh/uv/); it installs Python 3.13.

```bash
uv sync                                   # Python 3.13 and the locked dependencies
uv run veil --version
```

## Before you push

```bash
uv run ruff check . && uv run ruff format --check .
uv run python -m pytest --testmon-noselect -n auto -q    # the full suite, in parallel
```

- While you work, run only what your change touches: `uv run python -m pytest --testmon -q`.
- Platform code: run the opt-in tests on a real machine too (see `docs/macos.md`).
- New behaviour needs a test that fails without it: the happy path, edge cases (Unicode and
  Indic scripts, empty values, boundaries) and failure modes.
- Code in `src/veil/engine/` also needs property tests (hypothesis).

## Rules the linter and tests enforce

- Only `src/veil/ui.py` prints. Everything else returns values or raises.
- No `logging`, no `yaml.load` (use `veil.persona.yamlio`), no `tempfile.NamedTemporaryFile`.
- Messages and errors never contain persona values; field paths, counts and fake-side text only.

## Privacy

- Never commit real personal data: not in code, tests, fixtures, docs, logs or commit messages.
  Tests use the synthetic persona Jane Doe → Alex Smith (`tests/fixtures/synthetic_jane.yaml`).
- Your `persona.yaml` is git-ignored; `persona.example.yaml` is the blank template.
- Commit with your GitHub noreply address
  (`git config user.email <id>+<user>@users.noreply.github.com`).
- Fail closed: on any error veil clears the clipboard or refuses; it never lets real text through.
  Errors never switch veil off.

## Pull requests

1. Fork the repository and branch per task, named `<area>/<short-task>` (e.g. `macos/t1-ci`).
2. Open the pull request into `main`. One topic per pull request; describe what changed and why,
   and link the issue.
3. CI (lint, tests on Linux and macOS, sign-off) must pass, and the owner must approve. On your
   first pull request, CI waits until the owner allows it to run. The owner merges; `main` is
   protected.

- Commits follow Conventional Commits (`fix(engine): ...`, `feat(macos): ...`).
- Design changes (a new platform backend, a new dependency, a change in behaviour) are discussed
  in an issue or the pull request description first: what, why, alternatives.
- Platform-specific code goes behind the existing interfaces (`Clipboard`, `Notifier`,
  `SecretBackend`, `Watcher`, `Timers`) and is picked by `sys.platform` in the matching
  `detect()` function. Shared code stays shared.

## License

Keep the attribution in `NOTICE` and `veil --version` intact (GPL-3.0 section 7(b)). A modified
version must say that it is modified (section 7(c)).
