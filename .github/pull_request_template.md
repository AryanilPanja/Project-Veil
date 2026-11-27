## What and why

<!-- One task per pull request. What does it change, and why? Link the issue if there is one. -->

## How it was tested

<!-- New tests (happy path, edge cases, failure modes), and the platform(s) you ran them on. -->

## Checklist

- [ ] Every commit is signed off (`git commit -s`): I certify the DCO and license this under GPL-3.0 with the NOTICE attribution term
- [ ] No real personal data anywhere in this pull request (code, tests, docs, commit messages); tests use the synthetic persona
- [ ] `uv run pytest -q` passes locally
- [ ] `uv run ruff check . && uv run ruff format --check .` passes
- [ ] Output and logs show field paths, counts and fake-side text only, never real values
- [ ] Design changes (new backend, dependency, behaviour) are described above
