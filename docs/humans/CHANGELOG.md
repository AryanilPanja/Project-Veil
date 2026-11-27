# CHANGELOG

> **Audience:** the owner and users: what changed, in plain words.
> **Update when:** at every release (or every merged user-visible change, if there are no releases).
> **Last updated:** 2026-11-27

## Unreleased (towards v0.1.0)

### Added
- Encrypted persona: write it from `persona.example.yaml`, check it (`veil persona check`),
  import it (`veil persona import`), edit it safely (`veil persona edit`), see its health
  (`veil persona status`).
- Translation engine: names in many spellings and scripts, emails, paths, handles, phone and date
  formats, IDs with same-shape fakes, dates shifted by a constant.
- `veil translate`, `veil reverse`, `veil audit` for terminal use.
- Clipboard hotkeys on KDE Plasma 6: sanitize (Meta+Alt+V), sanitize the selection
  (Meta+Alt+C), restore (Meta+Alt+E), sanitize-and-paste (Alt+V, Alt+Shift+V).
- veil ON/OFF (Meta+Alt+K): while ON, every copy is sanitized; OFF needs a click or a typed
  `off`; an alarm if the watcher stops while ON.
- Ask before sending listed sensitive terms (Allow / Generalize / Deny).
- Notifications with counts per kind, never values; fail-closed clipboard on any error; the
  original removed from KDE's clipboard history.
- Contributor setup: GPL-3.0 with attribution (NOTICE), CONTRIBUTING, DCO sign-off check,
  ROADMAP with GitHub issues.

### Known gaps
- Typing directly into a chat box, images and files, middle-click paste, names not in your
  persona, Indic case endings glued to a name. See [OVERVIEW](OVERVIEW.md#what-it-doesnt-do-yet).
