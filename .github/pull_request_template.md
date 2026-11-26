## What and why

<!-- One task per pull request. What does it change, and why? Link the issue if there is one. -->

## How it was tested

<!-- New tests (happy path, edge cases, failure modes), and the platform(s) you ran them on. -->

## Checklist

- [ ] I have signed the Project Veil Contributor Agreement (version 1) and sent it to the owner
- [ ] No real personal data anywhere in this pull request (code, tests, docs, commit messages); tests use the synthetic persona
- [ ] `uv run pytest -q` passes locally
- [ ] `uv run ruff check . && uv run ruff format --check .` passes
- [ ] Output and logs show field paths, counts and fake-side text only, never real values
- [ ] Design changes (new backend, dependency, behaviour) are described above
