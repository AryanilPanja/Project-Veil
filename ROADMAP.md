# Roadmap

What's done, what's next, and what you can pick up. This is the public summary of the
maintainer's internal plan; it's updated when a milestone moves. To claim a task, open an issue
titled `claim: <task>` (or comment on an existing one) before you start, so two people don't build
the same thing. Workflow and rules: [CONTRIBUTING.md](CONTRIBUTING.md).

_Last updated: 2026-11-27._

## Where things stand

| Milestone | What | Status |
|---|---|---|
| M0 | Persona schema, validation, encrypted storage (age + keyring), `veil persona import/check/edit/status` | ✅ done |
| M1 | Translation engine: variants, compositional mapping, matcher, forward/reverse, `veil translate/reverse/audit` | ✅ done |
| M2 | Clipboard: sanitize/restore, plain-text-only write-back, notifications, ask-before-send, fail-closed, clipboard-history cleanup | ✅ done (Linux, KDE Plasma 6 / Wayland) |
| M3 | veil ON/OFF (a copy watcher sanitizes every copy), agent-proof kill switch, KDE hotkeys, sanitize-and-paste | ✅ done (Linux) |
| **M4** | **Site test matrix → release v0.1.0** | 🟡 tools ready; the maintainer runs the matrix |
| **macOS port** | Same features on macOS | 🟡 in review ([#13](https://github.com/AryanilPanja/Project-Veil/pull/13), being split) |
| v0.2.0 | Local proxy for Claude Code | ⏳ not started |
| v0.3 | Unknown-name detection (lightweight NER) | 💡 proposed |

## Now: v0.1.0

**M4: site test matrix** (maintainer). Run each case on claude.ai, ChatGPT, Gemini and a generic
page, in Firefox and Chromium: plain text, rich text, a 50 KB terminal dump, Bengali/Devanagari
names, restore, ask-before-send, veil ON/OFF, sanitize-and-paste. The offline test page and slot
template are in `tests/manual/site-matrix/`. Issues found become fixes with regression tests,
then release notes and the `0.1.0` tag.

**macOS port** (in progress, one pull request per step, in this order):

1. Engine and CLI fixes found during the port.
2. macOS backends + a macOS CI job: Keychain, pasteboard, copy watcher (launchd), notifications,
   RAM disk for plaintext, hardening, shortcuts.
3. Images (metadata stripped) and rich-only text (converted, then sanitized). **Accepted** by the
   maintainer.
4. `veil agent-guard` (Claude Code hooks and sandbox settings), on its own, last.

Rules for these: keep the required CI check name `lint + tests (Python 3.13)`; Linux behaviour
unchanged unless a pull request says otherwise; tests for every backend with fakes, real-system
tests opt-in.

## Next: v0.2.0, a local proxy for Claude Code

Claude Code talks to a local proxy that translates every request (system prompt, messages, file
contents, tool output) into the persona and reverse-translates the answers and tool calls, so the
agent keeps working on your real files. Shares the engine and persona store with v0.1.

| Step | Contents | Done when |
|---|---|---|
| P1 | Proxy, non-streaming: Starlette app, the JSON walker over system/tools/messages/tool results, forward memo, replay cache, token counting, fail closed, local auth token | Integration tests with a fake upstream; canary leak test finds 0 |
| P2 | Streaming: SSE reassembly, holdback restorer, buffered tool calls, thinking blocks and `ping` passed through untouched | Golden SSE suite; chunk-invariance property tests |
| P3 | Hardening: taint tracking, `never_reverse`, ask-before-send (hold the request), `veil sent/diff/approve` | Spec tests |
| P4 | Kill-switch levels: passthrough, bypass launcher, dead-proxy handling | Level tests |
| P5 | End to end with real Claude Code and the test persona | Leak audit 0, an edit task succeeds, a 30-turn thinking session without signature errors, cache reads > 0 |

Invariants that any proxy code must keep: fail closed (never forward untranslated content);
never modify `thinking` / `redacted_thinking` blocks or signatures; history is append-only (a
block once sent is re-sent byte-identical); pass unknown blocks, fields, headers and SSE events
through, never drop or reorder them.

Before P1 starts, a design note reconciles the proxy's kill switch with veil ON/OFF as v0.1
built it. Ask the maintainer before picking up P1.

## Later (open for discussion)

- **Unknown-name detection** (v0.3): a small NER pass that proposes names not in the persona,
  shadow mode first.
- **Browser extension** (Firefox + Chromium): cover typing, not just pasting.
- **Other agents** using the OpenAI API format (Codex, Aider, OpenCode).
- **Media**: PDF text rewriting, OCR + blur for images.
- **Linux desktops beyond KDE**: GNOME, Sway/Hyprland (wl-clipboard works; shortcuts and the
  copy watcher need checking), X11.

## Smaller tasks anyone can pick up

Self-contained, no design decision needed (still claim them first):

- **CI / supply chain:** pin GitHub Actions to full commit SHAs (e.g. with `pinact`); add a
  dependency audit step (`uv export --frozen --no-hashes` → `pip-audit` or osv-scanner).
- **Engine:** warn when a forward translation produces a `never_reverse` phrase (restore would
  silently leave it).
- **Engine coverage** (each needs a short design note first, since most raise false-positive
  risk): a name split by a hyphenated line break, Indic case endings glued to a name, homoglyphs
  (Cyrillic `а` for Latin `a`).
- **CLI robustness:** install `sys.excepthook` before argument parsing, so even an import-time
  error uses veil's error format.
- **Clipboard:** also remove the original from Klipper's history after a Deny or an error;
  cover the PRIMARY selection (middle-click paste).
- **Docs:** a public getting-started guide (the README links one that isn't published yet).

## How decisions are made

Small fixes: just open a pull request. Anything that changes behaviour, adds a dependency or a
platform backend: describe it first (an issue or the pull request description: what, why,
alternatives). The maintainer records the decision; ask for the background on any area you
touch.
