# OPERATIONS: running and maintaining Project Veil

> **Audience:** whoever runs veil (usually on their own desktop) or maintains the repository.
> **Update when:** how it's installed, run, released, upgraded, backed up or rolled back changes.
> **Last updated:** 2026-11-27

Everything runs on **your own Linux desktop** (KDE Plasma 6, Wayland) unless a row says
"GitHub". There is no server.

## Run locally (development)
```bash
uv sync                                               # install from uv.lock
uv run veil --version
uv run pytest -q                                      # full suite, ~2,750 tests, a few minutes
uv run ruff check . && uv run ruff format --check .   # lint + format
HYPOTHESIS_PROFILE=ci uv run pytest -q                # stronger property tests (what CI runs)
```
Try veil without a real persona: `export XDG_CONFIG_HOME=$(mktemp -d)`, then
`uv run veil persona import tests/fixtures/synthetic_jane.yaml` and `uv run veil persona status`.

## Install for daily use
1. Requirements: `uv`, `wl-clipboard`, `notify-send` (libnotify), a Secret Service keyring (KDE
   Wallet), a systemd user session.
2. `uv sync`, then write your persona from `persona.example.yaml` and check it:
   `uv run veil persona check --file <your-file>`.
3. `uv run veil persona import <your-file>` (encrypts it; keep or shred the plaintext).
4. `uv run veil install-shortcuts`, then `uv run veil install-shortcuts --status` (every line
   "ok").
5. Press Meta+Alt+K to switch veil ON, copy a line with one of your details, paste: you should see
   the fake.

## Build / release (maintainer, GitHub)
1. Release gate: the site test matrix passes (issue #15).
2. Version in `pyproject.toml`, release notes in [CHANGELOG.md](CHANGELOG.md).
3. PR into `main` (signed-off commits, CI green), merge, tag `vX.Y.Z`, push the tag.

## Upgrade
`git pull` then `uv sync`. If the watcher service changed, switch veil **OFF and ON once** so
systemd loads the new unit. Your persona and key are untouched by upgrades.

## Backups and restore
- Back up `~/.config/veil/persona.age` **and** the key (the keyring entry `project-veil` /
  `age-identity-v1`, or `key.age` in passphrase mode). One without the other is useless.
- `persona.age.bak` is the previous version, kept automatically on every save.
- Not needed in a backup: `persona.cache.age` (rebuilt), `state`, the runtime folder.

## Rollback
- Code: check out the previous tag and `uv sync`.
- Persona: `persona.age.bak` holds the previous save.
- Hotkeys: `uv run veil install-shortcuts --remove`. Watcher: switch veil OFF.

## Logs, health and troubleshooting
`uv run veil status` (ON/OFF), `uv run veil persona status` (store, key, unlock, runtime dir,
swap). `VEIL_TIMINGS=1` shows where time goes.

| Symptom | Check | Fix |
|---|---|---|
| "veil error: clipboard cleared" | `veil persona status` | Usually a locked keyring: unlock KDE Wallet, copy again |
| "veil isn't running" while ON | `systemctl --user status veil-watch` | Switch veil OFF and ON |
| "clipboard NOT sanitized: no plain text" | What you copied (rich text or an image) | Copy as plain text; don't paste it into a chat |
| A detail wasn't replaced | Is that spelling in your persona? | Add it as an alias; `veil persona check` |
| Hotkeys do nothing | `veil install-shortcuts --status` | Re-run `veil install-shortcuts`; pick another key with `--key` |
| CI is red on a PR (GitHub) | `gh pr checks N`, `gh run view <id> --log-failed` | Fix the failing test; rebase on `main` |
| A PR waits for a check that never runs (GitHub) | The job name vs the ruleset's required checks | Keep `lint + tests (Python 3.13)` and `DCO sign-off` names |
