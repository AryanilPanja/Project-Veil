# Project Veil: what it is and how it works

> **Audience:** the owner, users and contributors. Plain language; no code needed.
> **Update when:** what the project does, or how someone experiences it, changes.
> **Last updated:** 2026-11-27

## In one paragraph
veil keeps your personal details out of AI chats. Before text leaves your machine, it swaps your
real details (name, email, university, usernames, home folder, phone…) for a **consistent fake
persona**: "Jane Doe" always becomes "Alex Smith", her university always becomes the same other
university, and her email and paths become matching fakes. The AI still gives useful answers about
"Alex". When you copy the answer back, veil swaps the fakes back to your real details. Because
every real detail has exactly one fake (and the other way round), the swap is reversible.

## What it does
| You want to… | You do | veil does |
|---|---|---|
| Ask an AI something that mentions you | Copy the text, press **Meta+Alt+V**, paste into the chat | Replaces your details with the persona's, leaves plain text only on the clipboard |
| Not think about it at all | Press **Meta+Alt+K** once ("veil ON") | Every copy is sanitized automatically until you switch it OFF |
| Read the answer with your real details | Copy the answer, press **Meta+Alt+E**, paste | Swaps the fakes back |
| Paste in one go | **Alt+V** (Alt+Shift+V in a terminal) | Sanitizes, then pastes for you |
| Check or translate text in a terminal | `veil translate`, `veil audit` | The same translation on stdin/stdout |

Notifications say what was replaced **by kind and count only** ("name 2, email 1"), never the
values.

## How it works (the flow)
1. **Your persona** (real ↔ fake pairs) lives on your machine, **encrypted** (age encryption; the
   key sits in your desktop keyring). It's written once from a template and validated: every real
   form must map to exactly one fake form.
2. **Matching:** veil expands each detail into the ways it's written (case, initials, joined
   names, email and path parts, other scripts such as Bengali or Devanagari) and finds them all in
   one pass.
3. **Sanitize:** the clipboard text is read as plain text, translated real → fake, and written
   back as plain text only (rich copies can't smuggle the original through).
4. **Sensitive terms** you've listed (health, religion…) make veil **ask first**: Allow,
   Generalize (replace with a vague phrase) or Deny.
5. **Restore:** the reverse translation on a copied answer; leftover fake-name pieces it can't
   restore are flagged.

## When things go wrong
veil **fails closed**: if anything fails while sanitizing (a locked keyring, a broken clipboard
tool, an internal error), it **clears the clipboard** and shows a critical notification rather
than risk you pasting the original. An error never switches veil OFF; only you do (with a typed
`off` or one click).

## What it doesn't do (yet)
- It covers **pasted** text, not typing directly into a chat box (a browser extension is planned).
- Images and files pass through unchanged today (image metadata stripping is accepted and
  lands with #19).
- Middle-click paste (the PRIMARY selection) bypasses veil.
- It only knows the details in your persona: an unlisted name passes through (name detection is
  planned).
- Platforms: Linux with KDE Plasma 6 on Wayland is the tested target; macOS is in progress; see
  the README's platform table.
- v0.2 (planned): a local proxy so coding agents such as Claude Code get the same protection.

## Privacy and data
- Your persona and its key **never leave your machine**; veil makes no network connections.
- Plaintext appears only in memory, or briefly in an in-memory (tmpfs) folder while you edit the
  persona.
- Logs, errors and notifications contain counts, codes and field paths, never your values.
- veil **reduces** what you reveal; it doesn't make you anonymous. Your AI account already
  identifies you, and unique content (your actual code or research) can too.
