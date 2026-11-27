# DECISIONS: what was decided, by whom, and why

> **Audience:** the owner, contributors and every agent (agents read this before proposing changes).
> **Update when:** a choice is made that someone might later question: technology, design, defaults, trade-offs, reversals.
> **Last updated:** 2026-11-27

The full records are the maintainer's ADRs (Architecture Decision Records, kept locally,
ADR-0001 … ADR-0033). This is the public summary of the ones that shape the project.

## Owner decisions
| Date | Decision | Why | Revisit if |
|---|---|---|---|
| 2026-10-24 | A realistic, **consistent fake persona** instead of placeholders like `[NAME]` | The AI keeps giving useful, natural answers; the swap is reversible | A model starts treating persona text worse than placeholders |
| 2026-10-24 | Release order: **v0.1 clipboard + CLI** for web chats first, **v0.2 proxy** for coding agents next | The clipboard works with any chat site today; the proxy needs more machinery | — |
| 2026-10-24 | **Fail closed** everywhere; errors never switch veil off | Pasting a believed-sanitized original is the real danger | — |
| 2026-10-25 | Persona encrypted with **age**; key in the desktop keyring | Nothing in plaintext at rest; no passphrase prompt on every hotkey | Another platform needs another key store (macOS: Keychain) |
| 2026-10-25 | **Strict bijection** between real and fake forms, validated at load | Makes restore exact and catches persona mistakes early | — |
| 2026-10-25 | **Ask before sending** listed sensitive terms (Allow / Generalize / Deny) | Some details shouldn't go out even as fakes without a decision | — |
| 2026-10-25 | After sanitizing, **remove the original from KDE's clipboard history** | Otherwise the history pastes the real text back | — |
| 2026-10-26 | **veil ON = every copy is sanitized** (a copy watcher); OFF = normal; OFF needs a human action | The owner's flow: switch on once, then just copy and paste | — |
| 2026-10-26 | Rich-text-only copies left alone with a warning | Couldn't sanitize them safely | **Revised 2026-11-27:** accepted to convert them to plain text and sanitize them; lands with #19 |
| 2026-11-27 | **GPL-3.0-only** with an attribution term (section 7(b), in NOTICE); contributions by **DCO sign-off** | Open to contributors; derived works stay open and credit the project | — |
| 2026-11-27 | Outside contributions via **pull requests** into a protected `main` (CI + DCO required, 1 approval) | Review and CI gate every change | — |
| 2026-11-27 | Images: **strip metadata** from copied images (malformed images clear the clipboard); accepted, lands with #19 | EXIF/GPS and text chunks can identify you | — |
| 2026-11-27 | macOS port lands as **four PRs** (engine fixes, backends, images/rich text, agent-guard) | Reviewable pieces | — |
| 2026-11-27 | Internal design docs stay **local**; public docs are README, CONTRIBUTING, ROADMAP, `docs/humans/` | Design notes mention private details | Before the repo is promoted widely |

## Build defaults (made during the work; the owner can overturn)
| Date | Decision | Why | Revisit if |
|---|---|---|---|
| 2026-10-25 | Python 3.13 via `uv`; few runtime dependencies | Reproducible installs; fast hotkey start | — |
| 2026-10-25 | Matching with Aho-Corasick over all forms, checked against a slow reference translator | One pass over the text; correctness by property tests | — |
| 2026-10-25 | Encrypted compiled-lexicon cache for fast starts | Hotkey budget ~250 ms | — |
| 2026-11-27 | `GPL-3.0-only` rather than `-or-later` | The owner said "GPL 3.0"; widening later is possible, narrowing isn't | The owner wants future GPL versions |
| 2026-11-27 | Docs split into `docs/agents/` (local) and `docs/humans/` (public) | Agents need dense rules and private state; people need plain explanations | — |
