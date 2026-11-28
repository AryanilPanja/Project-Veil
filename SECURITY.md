# Security policy

## Reporting a vulnerability

- Use GitHub's private reporting: the repository's **Security** tab > **Report a
  vulnerability**. Do not open a public issue.
- Include: what an attacker can do, the steps or a script that shows it, the veil version
  (`veil --version`) and your OS.
- Never send your real persona, key or clipboard contents. Reproduce with the synthetic
  persona in `tests/fixtures/` or a made-up one.
- You get a first reply within 7 days. A fix for a confirmed issue ships as a patch release,
  with credit in the notes unless you ask otherwise.

## Supported versions

Only the latest release and `main` get fixes while the version starts with 0.

## What counts

veil's job is to keep real personal details out of text that leaves the machine. In scope:

- Real details that survive `veil translate`, a clipboard sanitize, or the copy watcher
  (a missed form, a Unicode trick, a timing gap that is not documented).
- Real details written anywhere outside the encrypted store and the in-memory runtime
  directory (tmpfs on Linux, the RAM disk on macOS): logs, notifications, error messages,
  temp files, shell history.
- Reading the key or persona without the user's consent: other local users, a debugger, a
  coding agent running under `veil agent-guard`.
- A way for a coding agent to get around `veil agent-guard` (a denied command or edit that
  runs anyway, or a review that misses a removed test).

Out of scope, documented limits:

- veil reduces what you reveal; it does not make you anonymous. Your AI account, your writing
  style and unique content can still identify you.
- Images, PDFs and rich text are passed through unchanged.
- Malware already running as your user can read your clipboard and screen.
- On macOS, a paste within 0.25 s of a copy can carry the original (`docs/macos.md`).

## Design rules the code keeps

- Fail closed: on any error veil clears or blocks the clipboard instead of sending real text.
- Error messages and notifications carry field paths and counts, never values.
- Plaintext is written only to tmpfs (Linux) or a verified `ram://` disk (macOS); the process
  disables core dumps and debugger attach.
- No network access. veil never sends anything anywhere.
