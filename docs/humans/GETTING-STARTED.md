# Getting started with veil (v0.1)

> **Audience:** the owner and anyone setting veil up on their own desktop.
> **Update when:** installation, setup steps, hotkeys or the everyday flow changes.
> **Last updated:** 2026-11-27

## 1. What veil does

veil swaps your personal details for a consistent fake persona before text reaches an AI chat, and
swaps them back in the answer you copy back. "Jane Doe" becomes "Alex Smith" everywhere. All
examples below use the **synthetic** test persona from
[`tests/fixtures/synthetic_jane.yaml`](../../tests/fixtures/synthetic_jane.yaml), never a real one.
For the full picture, read [OVERVIEW.md](OVERVIEW.md).

## 2. What you need

| Requirement | Why | Check |
|---|---|---|
| Linux with **KDE Plasma 6 on a Wayland session** | the hotkeys, notifications and copy watcher are built for it | `echo $XDG_SESSION_TYPE` → `wayland` |
| **wl-clipboard** | reads and writes the clipboard | `command -v wl-copy wl-paste` |
| **notify-send** (libnotify) | notifications and the Allow / Generalize / Deny question | `command -v notify-send` |
| **KDE Wallet** (or another Secret Service keyring) | holds the key that encrypts your persona | open KWalletManager |
| **systemd user session** | runs the copy watcher while veil is ON | `systemctl --user status` |
| [uv](https://docs.astral.sh/uv/) | installs Python 3.13 and veil's dependencies | `uv --version` |

Other desktops and X11 are not supported by the v0.1 clipboard features yet; see the platform
table in [README.md](../../README.md).

## 3. Install

```bash
git clone <repository-url> project-veil
cd project-veil
uv sync
uv run veil --version
```

Run every `veil` command below from this folder as `uv run veil …`.

## 4. Your persona

The persona is a YAML file that pairs each **real** detail with the **fake** one the AI sees.

1. **Copy the template and keep it private:**

   ```bash
   cp persona.example.yaml persona.yaml
   chmod 600 persona.yaml
   ```

   `persona.yaml` is git-ignored. Start from the blank
   [persona.example.yaml](../../persona.example.yaml); never paste your real persona into an issue,
   a chat or an AI tool, including when asking for help.

2. **Fill it in.** The comments in the file explain each section. Shape, using only synthetic
   values:

   ```yaml
   person:
     full_name: { real: Jane Doe, fake: Alex Smith }
   emails:
     - { real: jane.doe@xyz.example.test, fake: alex.smith@abc.example.test }
   ```

   The rules that matter most:

   - each real value maps to **one** fake value; no fake may appear inside a real value (or the
     other way round), so answers can be translated back without guessing;
   - leave `real: ""` for details that don't apply;
   - numbers and IDs (phone, roll number, national ID…) can keep an empty fake with `policy: FPE`;
     veil generates a format-valid one;
   - choose fakes of a similar "tier" as the real thing (a comparable institution, a common name)
     so the AI's answers stay useful.

3. **Sensitive topics (optional).** Under `sensitive:`, list terms you would want to think twice
   about sending, with a generic replacement:

   ```yaml
   sensitive:
     health: { real: [asthma], generalized: "a chronic condition", policy: ASK }
   ```

   When copied text contains one, veil asks **Allow / Generalize / Deny** before anything reaches
   the clipboard. No answer within `ask_timeout_seconds` (default 120) counts as Deny.

4. **Check it** until it reports no errors. It prints field paths, codes and counts, never your
   values:

   ```bash
   uv run veil persona check --file persona.yaml --strict
   ```

5. **Import it** (validates, encrypts, and creates the key in your keyring; the keyring may ask you
   to unlock it):

   ```bash
   uv run veil persona import persona.yaml
   uv run veil persona status        # every line should say ok
   ```

   The plaintext file stays where it is. Keep it somewhere safe, or import with `--shred` to have
   veil overwrite and delete it (it asks you to type `shred`); add `--replace` when re-importing
   over an existing persona.

6. **Later changes:** `uv run veil persona edit` opens the encrypted persona in a hardened editor
   (plaintext lives only in memory and on tmpfs). Run this yourself, not from an AI tool.

`uv run veil persona status` may warn about **unencrypted swap**: memory can be written to disk in
plain text. Encrypted swap or zram fixes it (needs administrator rights).

## 5. Hotkeys

```bash
uv run veil install-shortcuts
uv run veil install-shortcuts --status   # every line should say "ok"
```

| Hotkey | What it does |
|---|---|
| **Meta+Alt+K** | veil ON / OFF. ON: every copy is sanitized. OFF: normal copy and paste (needs one click) |
| **Meta+Alt+V** | Sanitize what is in the clipboard |
| **Alt+V** | Sanitize, then paste (Ctrl+V) into the focused window |
| **Alt+Shift+V** | The same, pasting with Ctrl+Shift+V (terminals) |
| **Meta+Alt+C** | Sanitize the highlighted text into the clipboard |
| **Meta+Alt+E** | Restore: fake → real in the clipboard (for the AI's answer) |

Other details:

- A key already used by something else is reported, never taken. Choose another with
  `uv run veil install-shortcuts --key restore=Meta+Alt+X` (names: `sanitize`, `from-selection`,
  `restore`, `toggle`, `paste`, `paste-terminal`; repeatable).
- The shortcuts appear in System Settings → Keyboard → Shortcuts, under Commands.
- Without KDE, `uv run veil install-shortcuts --print` lists the commands to bind by hand.
- The first **Alt+V** shows a KDE permission dialog asking whether veil may control the keyboard
  (it only presses Ctrl+V or Ctrl+Shift+V). Allow it and let KDE remember.

## 6. veil ON and OFF

ON means a background watcher sanitizes **every** copy; OFF means normal copy and paste.

1. Press **Meta+Alt+K** to switch ON.
2. Copy as usual (Ctrl+C). A moment later the clipboard holds the sanitized text. Paste it into
   the chat with Ctrl+V.
3. Copy the AI's answer, wait a moment, press **Meta+Alt+E**, then paste to read it with your real
   details. veil recognises its own restore and does not sanitize it straight back. If you press
   restore within a split second of the copy and get the fake text, press Meta+Alt+E again.
4. When you finish chatting, press **Meta+Alt+K** → click **Switch OFF**.

While veil is ON:

- **every** copy is sanitized, including copies meant for your own files; Meta+Alt+E gives the
  real text back;
- images, files and password-manager copies are left alone;
- copied rich text with no plain-text version cannot be sanitized: you get a critical warning and
  the original stays on the clipboard — do not paste it into a chat;
- notifications appear only when something was replaced or needs attention;
- veil stays ON across a reboot until you switch it OFF;
- `uv run veil on --for 2h` switches OFF by itself after two hours;
- `uv run veil status` tells you whether the watcher is really running.

Turning ON never asks. Turning OFF needs a typed `off` (`uv run veil off`) or one click from the
hotkey, so a script or an AI agent cannot quietly switch your protection off. An error never
switches veil off either: it clears the clipboard instead.

Without ON, use one key at a time:

| You want to… | Do this |
|---|---|
| Send something | copy it, press **Alt+V**, or **Meta+Alt+V** then Ctrl+V |
| Send highlighted text | highlight it, press **Meta+Alt+C**, then Ctrl+V |
| Read an answer | copy it, press **Meta+Alt+E**, then Ctrl+V |

Each sanitize reports what it replaced **by kind and count only** ("name 2, email 1"), never the
values.

## 7. Walkthrough with the synthetic persona

With the synthetic persona imported, the line "Hi, I'm Jane Doe, an MS student at XYZIT." is
sanitized to "Hi, I'm Alex Smith, a PhD student at ABCU." Those are all invented values from the
fixture. The paste goes to the chat as plain text; the original stays off the clipboard.

To see the same thing without touching your real setup, in one terminal:

```bash
export XDG_CONFIG_HOME=$(mktemp -d)
uv run veil persona import tests/fixtures/synthetic_jane.yaml
echo "Hi, I'm Jane Doe, an MS student at XYZIT." | uv run veil translate
unset XDG_CONFIG_HOME
```

The hotkeys always use your real setup, not this throwaway folder.

| Notification | Meaning |
|---|---|
| "veil: sanitized, 3 replaced" | done; paste away |
| "veil: clipboard NOT sanitized" (critical) | no plain text (a rich copy or an image); do not paste it into a chat |
| "veil: withheld, clipboard cleared" | you chose Deny for a sensitive term |
| "veil error: clipboard cleared" (critical) | something failed; veil cleared the clipboard rather than risk the original — copy again |
| "veil: 2 restored" with a leftover-fake warning | a shortened or glued form of a fake name could not be restored; read the text before using it |
| "Original removed from Klipper's history." | the original will not come back from the clipboard history |

## 8. Known gaps

- Only text that is **copied and pasted** is covered; typing straight into a chat box is not.
- Middle-click paste (the PRIMARY selection) bypasses veil; use Ctrl+V.
- Images and file uploads pass through unchanged.
- veil only knows the details in your persona; an unlisted name passes through.
- Hyphenated names, glued Indic case endings, look-alike (homoglyph) characters and PRIMARY paste
  are open design issues: see [ROADMAP.md](../../ROADMAP.md), issues
  [#35](https://github.com/AryanilPanja/Project-Veil/issues/35),
  [#36](https://github.com/AryanilPanja/Project-Veil/issues/36),
  [#37](https://github.com/AryanilPanja/Project-Veil/issues/37) and
  [#40](https://github.com/AryanilPanja/Project-Veil/issues/40).

veil reduces what you reveal; it does not make you anonymous. Your AI account already identifies
you to the provider.

## 9. Troubleshooting

| Symptom | Try |
|---|---|
| a hotkey does nothing | `uv run veil install-shortcuts --status`, then re-run `uv run veil install-shortcuts` |
| veil ON but copies are not sanitized | `uv run veil status`; `journalctl --user -u veil-watch -n 30` |
| a key error (exit code 4: keyring locked or closed) | unlock KDE Wallet; `uv run veil persona status` |
| every copy gets cleared while ON | the key cannot be read (keyring locked): unlock it, or switch veil OFF |
| Alt+V sanitizes but does not paste | allow KDE's keyboard-control permission dialog; tap the keys, don't hold them |
| slow first run after a change | normal: veil rebuilds its encrypted cache once |

`VEIL_TIMINGS=1 uv run veil …` prints how long each step took (no values). More detail, including
backups and rollback, is in [OPERATIONS.md](OPERATIONS.md); decisions are in
[DECISIONS.md](DECISIONS.md).
