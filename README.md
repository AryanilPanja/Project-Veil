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

## Platform support

Veil is being built and tested on **one setup first: Linux, KDE Plasma 6 on Wayland** (Fedora).
Other platforms are not refused on purpose; they simply have not been built for or tested yet.

**Requirements (all platforms, today):**
- Linux with systemd: veil keeps temporary plaintext only in your login session's in-memory
  runtime directory (`/run/user/<uid>`, tmpfs) and refuses to run edits anywhere else.
- A Secret Service keyring (KDE Wallet, GNOME Keyring or KeePassXC) to hold the encryption key,
  **or** passphrase mode (no keyring needed; works over ssh, but cannot be used from hotkeys yet).
- [uv](https://docs.astral.sh/uv/) (installs Python 3.13 for you).
- For the v0.1 clipboard hotkeys: a Wayland session, `wl-clipboard` and `notify-send`.

| Platform | Persona, encryption, CLI (`veil translate`) | Clipboard hotkeys (v0.1) | Claude Code proxy (v0.2) |
|---|---|---|---|
| **Linux, KDE Plasma 6, Wayland** | ✅ target, tested | ✅ target (shortcuts installed by `veil install-shortcuts`) | ✅ target |
| Linux, GNOME, Wayland | 🟡 should work (GNOME Keyring is a Secret Service); untested | ❓ untested: GNOME may not let background tools read the clipboard; shortcuts must be added by hand | 🟡 should work; untested |
| Linux, other Wayland desktops (Sway, Hyprland…) | 🟡 should work with a Secret Service keyring or passphrase mode | 🟡 likely (they support `wl-clipboard`); shortcuts by hand | 🟡 should work |
| Linux, X11 session | 🟡 core should work | ❌ not supported (needs `xclip`/`xsel` support) | 🟡 should work |
| Linux without systemd / no `/run/user` tmpfs | ❌ `persona edit` refuses (no safe place for plaintext) | ❌ | ❌ |
| macOS | ❌ not supported yet (no tmpfs runtime dir, Keychain not wired up) | ❌ | ❌ |
| Windows | ❌ not supported yet (uses Unix-only file locking and permissions) | ❌ | ❌ |
| WSL | ❌ untested; no desktop keyring by default | ❌ | ❌ |

✅ supported and tested · 🟡 expected to work, untested · ❓ unknown · ❌ not supported

Porting to other platforms is planned for later. The design keeps the platform-specific parts
(file safety, keyring, clipboard, hotkeys) in small modules so they can be swapped.

## Limits
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

## Current maintainers
- Claude (Mastermind + Orchestrator)
- Me (Dumb Human)

## License
Proprietary: all rights reserved. The source is publicly visible, but no permission is granted to use, copy, modify, or distribute it. See [LICENSE](LICENSE).
