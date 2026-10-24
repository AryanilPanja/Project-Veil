# Project Veil

Keep your personal information out of AI chats and coding agents by **translating it into a
consistent fake persona** before text leaves your machine, and translating the answers back.

"Jane" always becomes "Alex", her university becomes another university, and her username,
email, home path and roll number all become matching fakes. The AI still gives useful answers
about "Alex"; you get them back with your real details restored.

> **Status: early development (v0.1.0 in progress).** Not ready for use yet.

## Planned releases
| Release | What |
|---|---|
| **v0.1.0** | Web chats (claude.ai, ChatGPT, Gemini, any site): a clipboard hotkey sanitizes text before you paste; another restores real details in a copied answer. Plus a `veil` CLI (`veil translate`, `veil reverse`) |
| v0.2.0 | A local proxy for Claude Code: translates every request, including file contents and tool output, and reverse-translates the agent's tool calls so it keeps working on your real files |
| Later | Detection of unknown names, a browser extension, other agents |

## How it works (in short)
- **Your persona** (real ↔ fake mapping) is stored **encrypted** on your machine (age encryption,
  key in your desktop keyring) and is never sent anywhere.
- Every real form maps to exactly one fake form (a strict one-to-one mapping), so translation
  is reversible.
- Matching is Unicode-aware: case-insensitive, robust to invisible characters and full-width
  letters, and handles Indic scripts correctly (names inside longer words are not matched).
- Failures are **fail-closed**: on any error veil blocks or clears rather than sending real data.

## Honest limits
Veil **reduces** what you reveal; it does **not** make you anonymous. Your AI account already
identifies you to the provider, unique content (your actual code or research) can identify you,
and images/PDFs are passed through unchanged for now.

## Development
Requires [uv](https://docs.astral.sh/uv/) (it installs Python 3.13 for you).

```bash
uv sync                     # create the environment
uv run veil --version
uv run pytest -q            # unit + property tests
uv run ruff check . && uv run ruff format --check .
```

CI runs the same checks on every push and pull request (`.github/workflows/ci.yml`).

## Privacy rules for contributors
- Never commit real personal data: not in code, tests, fixtures, logs or commit messages. Tests
  use a synthetic persona (Jane Doe → Alex Smith).
- Your real persona file (`persona.yaml`) is git-ignored; `persona.example.yaml` is the blank
  template.
- Use your GitHub noreply address as your git commit email.

## License
Not yet chosen; all rights reserved until a license is added.
