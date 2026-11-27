# ARCHITECTURE: how Project Veil fits together

> **Audience:** a technical owner or contributor who wants the big picture before reading code.
> **Update when:** a component, data store, external dependency or major flow is added/removed/changed.
> **Last updated:** 2026-11-27

## The system on one screen
```
 persona.age (encrypted) ──► persona/ (schema, validation, store) ──► engine/ (lexicon, matcher)
        ▲  key in the desktop keyring (crypto/)                          │ forward / reverse
        │                                                                ▼
 veil persona import/edit            ┌──────────── v0.1: clipboard + CLI ────────────┐
                                     │ clip/ sanitize · restore · ask · notify       │
   Meta+Alt+V / E / K, Alt+V ──────► │ killswitch.py: veil ON = copy watcher service │
   (shortcuts.py installs them)      │ textcmd.py: veil translate / reverse / audit  │
                                     └───────────────────────────────────────────────┘
                                     ┌──────────── v0.2 (planned): local proxy ──────┐
   Claude Code ──► 127.0.0.1 ──────► │ requests real→fake; responses, tool calls     │ ──► AI API
                                     │ fake→real; same persona + engine              │
                                     └───────────────────────────────────────────────┘
```

## Components
| Component | Path | Responsibility |
|---|---|---|
| CLI | `src/veil/cli.py`, `ui.py`, `errors.py`, `exitcodes.py` | The `veil` command; all output via `ui.py`; value-free errors; one exit-code table |
| Safety base | `paths.py`, `fsutil.py`, `hardening.py` | Where files go (tmpfs-only plaintext), careful atomic writes and locks, no core dumps |
| Encryption | `crypto/age.py`, `crypto/keystore.py` | age encryption; the key in the Secret Service keyring (or a passphrase file) |
| Persona | `persona/` | Strict schema, safe YAML, validation (bijection + rules), the encrypted store, import/edit/status, a canary marker |
| Text | `text/` | Normalization (`canon()`), the word-boundary rule, Aho-Corasick search |
| Engine | `engine/` | Variants and compositional mapping → lexicon → matcher (`Engine.forward/reverse`); a slow reference translator as the test oracle; generated fakes; encrypted cache |
| Clipboard | `clip/` | Plain-text clipboard I/O (wl-clipboard), sanitize/restore, ask-before-send, notifications, Klipper history cleanup, the copy watcher, sanitize-and-paste via the XDG portal |
| veil ON/OFF | `killswitch.py` | The `veil-watch` systemd user service (the source of truth), state, timers, one-click OFF |
| Hotkeys | `shortcuts.py` | KDE Plasma 6 shortcuts installed the way System Settings does it |
| Tests | `tests/` | Unit + property tests with the synthetic persona; fakes for every desktop service; the M4 manual test page |
| CI | `.github/` | DCO sign-off + lint + tests on every PR; Dependabot |

## Data model (in plain words)
- A **persona** has sections (person, emails, phones, handles, education, work, people, infra, ids,
  attributes, sensitive, footprint). Each field is a real value, a fake value and a **policy**:
  SWAP (use the fake), FPE (generate a same-shape fake), SHIFT (dates move by a constant),
  GENERALIZE, REDACT, KEEP (leave alone), ASK (ask before sending).
- Each value becomes an **entity** with many **forms** (spellings). The **lexicon** holds every
  real form and its fake, and the reverse. Validation guarantees a **strict bijection**: no fake
  form inside a real one or the other way round.
- **Compositional** values (emails, paths, URLs, handles) are split into parts and mapped part by
  part, so every form of them stays consistent.
- Generated fakes and a seed live in an encrypted **vault**; a compiled **cache** speeds up the
  hotkey (safe to delete).

## Key flows
1. **Sanitize:** read `text/plain` → load the engine (cache, else decrypt + build) → forward
   translate → ask about sensitive terms → write `text/plain` only → drop the original from
   Klipper's history → notify counts. Any error → placeholder, clear, critical notification.
2. **veil ON:** `veil on` writes and starts the `veil-watch` user service: `wl-paste --watch`
   runs one sanitize per copy; veil's own writes are skipped once; if the service dies, a check
   5 s later raises an alarm (veil never switches itself OFF).
3. **Restore:** reverse translate a copied answer; flag leftover fake-name pieces; on error the
   clipboard is left as it was.

## Where veil keeps things
| Where | What |
|---|---|
| `$XDG_CONFIG_HOME/veil/` (`~/.config/veil/`) | `persona.age` (+ `.bak`), `recipient.txt`, `persona.vault.age`, `persona.cache.age`, `persona.draft.age`, `persona.lock`, `state`, `paste-portal-token`; `key.age` only in passphrase mode |
| Desktop keyring (Secret Service) | The private key: service `project-veil`, entry `age-identity-v1` |
| `$XDG_CONFIG_HOME/systemd/user/veil-watch.service` | The copy watcher (written by `veil on`) |
| `$XDG_DATA_HOME/applications/net.local.veil-*.desktop` | One per hotkey (`veil install-shortcuts`) |
| `$XDG_RUNTIME_DIR/veil/` (tmpfs, 0700) | Plaintext only during `veil persona edit`; the own-write guard (hashes, never text) |

## Configuration
- Paths follow `XDG_CONFIG_HOME`, `XDG_DATA_HOME`, `XDG_RUNTIME_DIR`. A throwaway config folder
  gets its own keyring entry, so test stores never collide with the real one.
- `VEIL_TIMINGS=1` prints value-free stage timings.
- Hotkeys: `veil install-shortcuts [--key NAME=KEYS]`.

## Security model
- Threat: real details leaking to an AI provider (or to a coding agent on the same machine).
- Persona encrypted at rest; key in the keyring; plaintext only in memory or tmpfs; process
  hardened (no core dumps, non-dumpable); errors and logs value-free.
- **Fail closed** on every path that could let a real value through.
- Agents working on this repo are blocked from the persona, the key, the clipboard and the
  ON/OFF switch by deny rules (and, planned, `veil agent-guard`).
- Not covered: your AI account identifying you; unique content; images/files (today); typing
  into the page.

## Where to change X
| I want to change… | Edit | Notes |
|---|---|---|
| What counts as a word boundary | `src/veil/text/boundary.py` | Shared by validator and matcher; property tests |
| Which spellings of a value match | `src/veil/engine/variants.py`, `compose.py` | Keep the bijection; add tests in `tests/unit/test_variants.py` |
| Matching itself | `src/veil/engine/matcher.py` | Must agree with `engine/reference.py` (property tests) |
| The persona schema | `src/veil/persona/schema.py`, `persona.example.yaml` | Bump the schema version for breaking changes |
| Clipboard behaviour | `src/veil/clip/commands.py`, `io.py` | Fail closed; plain text only |
| What a notification says | `src/veil/clip/messages.py`, `notify.py` | Counts and kinds only |
| ON/OFF behaviour | `src/veil/killswitch.py`, `clip/watch.py`, `clip/recent.py` | OFF needs a human action |
| Hotkeys | `src/veil/shortcuts.py` | KDE-specific |
| A new platform | the modules above behind their interfaces (`keystore`, `clip/io`, `killswitch`, `shortcuts`, `paths`, `hardening`) | See the macOS port (PR #13) |
