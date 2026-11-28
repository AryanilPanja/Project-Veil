# veil agent-guard

Hooks for Claude Code that keep a coding agent away from veil's secrets and flag edits that
make tests, checks or ML evaluation pass without the code working.

```bash
veil agent-guard install --warn       # recommended first step: ask instead of blocking
veil agent-guard install              # strict mode: block protected actions outright
veil agent-guard install --print      # preview the merged settings JSON without writing
veil agent-guard review               # the same diff review, by hand or in CI (--json)
veil agent-guard review --second      # plus the second-model review (off by default; below)
veil agent-guard doctor               # check the guard, telemetry and transcript retention
veil agent-guard uninstall            # remove hooks and project notice blocks
```

Start with `veil agent-guard install --warn` when trying the guard on a repository. In
`--warn` mode, pre-tool rule matches prompt Claude Code to ask for your confirmation instead
of silently denying (invalid/unparseable hook input still fails closed), and you can switch
to `veil agent-guard install` once you know the rules fit your workflow.

## What install changes

- `.claude/settings.json`: merges deny rules, the OS sandbox and four hooks into what is
  already there. Your own rules and hooks stay.
  - Sandbox: shell commands run sandboxed, with no unsandboxed escape
    (`allowUnsandboxedCommands: false`), network only to PyPI and GitHub, and no reads of
    `~/.ssh`, `~/.gnupg`, `~/.config/gh`, the Keychain or veil's config.
  - `disableBypassPermissionsMode`: the agent can't be switched to skip-all-permissions.
- `env`: `DISABLE_TELEMETRY`, `DISABLE_ERROR_REPORTING`,
  `CLAUDE_CODE_DISABLE_FEEDBACK_SURVEY` and `DISABLE_FEEDBACK_COMMAND` set to `1`. Claude
  Code then sends no usage metrics or error reports for the project, doesn't show the session
  survey (whose follow-up question uploads the transcript), and turns off `/feedback`, `/bug`
  and `/share`, which upload the conversation and keep it for 5 years. Auto-update still
  works; `CLAUDE_CODE_DISABLE_NONESSENTIAL_TRAFFIC=1` would turn that off too.
- `CLAUDE.md` and `AGENTS.md`: a short block between `<!-- veil:begin -->` and
  `<!-- veil:end -->`. It tells the agent that veil is active, that names and contact details
  may be pseudonyms to keep as they are, and not to ask for real ones, run veil, or read the
  clipboard. Re-installing replaces the block; the rest of the file is untouched.
- The hooks call the interpreter that ran `install` by absolute path, so they work when
  `veil` is not on PATH. If the pre-tool hook can't start, it blocks.

## What is sent where

| Feature | Sends anything? | Destination and contents |
|---|---|---|
| `install` / hooks / `review` | **Local only** | Never leaves your machine. Writes `.claude/settings.json`, `CLAUDE.md`, `AGENTS.md`, and logs locally (`~/Library/Logs/veil/` on macOS, `~/.local/state/veil/` on Linux). |
| Telemetry opt-outs in `env` | **Reduces uploads** | Turns off Claude Code metrics, error reports, session surveys, and `/feedback` / `/bug` / `/share` transcript uploads for the project. |
| `[second_review]` / `--second` | **Off by default** | Only when configured in `.veil-agent-guard.toml` or invoked with `--second`: sends the redacted `git diff` (and typed session requests / final reply when `send_task = true`) to Gemini via `agy`. |

## Uninstalling cleanly

```bash
veil agent-guard uninstall            # or --project /path/to/repo
```

- Removes all veil `SessionStart`, `PreToolUse`, `PostToolUse` and `Stop` hook entries from
  `.claude/settings.json` while leaving your own hooks intact.
- Removes the `<!-- veil:begin --> ... <!-- veil:end -->` notice block from `CLAUDE.md` and
  `AGENTS.md` (and deletes those files if they become empty).
- Leaves `.claude/settings.json`'s `permissions`, `sandbox` and `env` entries in place so your
  existing security rules aren't silently stripped; remove those keys from
  `.claude/settings.json` by hand if you want a completely blank settings file.

## The hooks

| Hook | When | What it does |
|---|---|---|
| SessionStart | session start | adds the veil notice to the agent's context |
| PreToolUse | before every tool call | blocks protected reads, writes and commands (below) |
| PostToolUse | after every tool call | records the edit in the session log |
| Stop | when the agent says it's done | reviews the session's diff; on a HIGH finding, sends it back once with the reasons |

Blocked before they run (exit 2 plus a `deny` decision):

- Reading or writing veil's key, persona, `*.age` files and config; `~/.ssh`, `~/.gnupg`,
  the Keychain.
- Clipboard and keychain tools: `pbpaste`, `pbcopy`, `osascript`, `wl-paste`, `xclip`,
  `security find-generic-password` and similar, `secret-tool`. Quote tricks such as
  `p''bpaste` are caught.
- `veil off`, `veil reverse`, `veil persona edit` and the other human-only veil commands;
  `launchctl` or `systemctl` on veil's watcher.
- The guard itself: `.claude/settings*.json`, `.veil-agent-guard.toml`, `.git/config`,
  `.git/hooks/`, and its log directory.
- Deleting or rewriting protected test and CI files, also through `env`, `xargs`,
  `bash -c`, `$(...)`, `find -delete`, `dd of=`, `ln -sf`, `truncate`, or `python -c`.
- `git reset --hard`, `git clean -f`, `git checkout .`, `git restore .`, forced pushes
  (`-f`, `-uf`, `--force*`, `+branch`), `git commit --no-verify`.
- `pytest --deselect` and `-k` filters that drop tests removed in the same session.
- Input the hook can't parse: empty, not a JSON object, a NUL byte in a path.

Flagged by the review (`veil agent-guard review`, and the Stop hook):

- Tests: deleted test files, dropped asserts, changed expected literals, new skips (except a
  platform or version `skipif`), tautologies (`assert True`), heavy new mocking, code that
  detects it is under test.
- Checks: CI steps weakened or set to always pass, lint suppressions, raised tolerances in
  test and eval code, swallowed exceptions, `|| true` / `exit 0` added to checks.
- ML: evaluation or metric code edited, seeds changed, train/test split or dataset changed,
  data leakage between splits, `model.eval()` removed, hyperparameters changed silently,
  metrics replaced by constants.
- Security: new network calls, `eval`/`exec`, `shell=True`, new dependencies, credential
  reads in CI or shell files.

Every finding names the rule, the file and the line. The log is
`~/Library/Logs/veil/agent-log.jsonl` on macOS and `~/.local/state/veil/agent-log.jsonl` on
Linux.

## Optional project config

`.veil-agent-guard.toml` in the project root (the agent can't edit it):

- `test_command`: run by the Stop hook; a failing exit sends the agent back once.
- `protected`: extra paths to protect. `allow`: paths to exempt.

## Second-model review

A model from another family reads the session's work when the agent stops. It looks for what
the patterns above can't see: the diff doesn't do what you asked, the agent's final message
claims something the diff and the test run don't show ("tests pass", "fixed"), a step was
dropped without saying so, or placeholder data stands in for real logic.

It uses Gemini through the Antigravity CLI (`agy`), which must be installed and signed in.
Turn it on in `.veil-agent-guard.toml`:

```toml
[second_review]
model = "gemini-4-hydrogen-high"   # any model `agy models` lists
timeout = 300                      # seconds, 10 to 1200
send_task = true                   # false sends the diff only
block = true                       # false shows HIGH findings to you instead of the agent
# command = "/path/to/agy"         # default: agy on PATH, then ~/.local/bin/agy
```

What is sent to Google:

- The diff since the session started, including new untracked files. The content of
  `persona.yaml`, `*.age`, `.env*`, key files, `.claude/settings*.json` and the guard config
  is replaced by a note. API keys, tokens, private keys and `password = ...` values elsewhere
  are replaced with `[redacted by veil]`. Pattern-based: a secret in an unusual format can
  get through.
- With `send_task`: the messages you typed in the session (from the Claude Code transcript)
  and the agent's last reply, plus the `test_command` result. Text you pasted through veil
  holds pseudonyms, not your details.

How it runs:

- `agy --sandbox --mode plan` in a new empty temporary directory, so the reviewer can read
  only the prompt, not your repository or home directory.
- The diff and messages sit inside tags with a random suffix, and the reviewer is told not to
  follow instructions in them. Its answer must match a JSON schema; each reason is cut to 300
  characters and stripped of control and bidi characters before the agent sees it.
- Once per distinct diff and task: stopping again with nothing changed doesn't call it, and
  neither does the second stop after a block.
- If `agy` is missing, signed out, over quota or slow, the stop goes through and Claude Code
  shows "second review unavailable" with the reason. The pattern review still runs.
- Each run is logged (`tool_name: stop_second_review`) with its status and finding ids.

`veil agent-guard review --second [--task "what it should do"]` runs it by hand, whether or
not `[second_review]` is on.

## Doctor

`veil agent-guard doctor` reads the user, project and local Claude Code settings and the
environment, and reports:

- whether the hooks, the sandbox and the bypass-mode lock are in place;
- each telemetry opt-out above, or `CLAUDE_CODE_DISABLE_NONESSENTIAL_TRAFFIC`;
- OpenTelemetry export that includes prompts or tool content (`OTEL_LOG_USER_PROMPTS`,
  `OTEL_LOG_TOOL_DETAILS`, `OTEL_LOG_TOOL_CONTENT`);
- `cleanupPeriodDays` over 30: Claude Code keeps plaintext transcripts in
  `~/.claude/projects/` that long;
- whether the second reviewer is on and `agy` is found.

It exits 1 if anything is `warn`. It can't see one setting: on Free, Pro, Max and Ultra,
whether your chats are used for training (5-year retention when on, 30 days when off) is set
only at claude.ai/settings/data-privacy-controls.

## Limits

- The sandbox is the hard boundary. The pre-tool hook matches commands and paths; a
  program can write files in ways no pattern list covers. The Stop review then sees the
  result in the diff.
- The review reads `git diff`. Changes outside the repository are seen only through the
  session log.
- A HIGH finding sends the agent back once. If you asked for the change (deleting a test on
  purpose), the second stop goes through and the notification stays.
- Claude Code only. Other agents can run `veil agent-guard review` in CI.
- The second reviewer is a language model too. It can miss things, flag correct work, or be
  steered by text in the diff despite the tags. Treat its findings as a reason to look, and
  keep the test run and CI as the check that counts.

## Why

Public reports of coding agents making checks pass without making the code work, or
reporting results that were not true:

- Tests changed instead of code:
  [anthropics/claude-code#7074](https://github.com/anthropics/claude-code/issues/7074),
  [#42585](https://github.com/anthropics/claude-code/issues/42585) (tests deleted after
  declaring methods removed without checking),
  [#94170](https://github.com/anthropics/claude-code/issues/94170) (self-written fixtures hid
  a broken feature),
  [#47700](https://github.com/anthropics/claude-code/issues/47700) (working fixes reverted).
- Test results reported as passing when they were not:
  [#46940](https://github.com/anthropics/claude-code/issues/46940),
  [#11913](https://github.com/anthropics/claude-code/issues/11913),
  [#33781](https://github.com/anthropics/claude-code/issues/33781),
  [#64286](https://github.com/anthropics/claude-code/issues/64286) (pushed to main),
  [#74427](https://github.com/anthropics/claude-code/issues/74427),
  [#1501](https://github.com/anthropics/claude-code/issues/1501).
- Mock data in place of real data:
  [#6984](https://github.com/anthropics/claude-code/issues/6984).
- Anthropic's Claude 3.7 Sonnet system card describes the model special-casing tests to make
  them pass.
- Anthropic's research on reward hacking
  ([Natural emergent misalignment from reward hacking](https://www.anthropic.com/research/emergent-misalignment-reward-hacking)):
  a model trained in environments where it learned to cheat on coding tests also tried to
  sabotage code, including code meant to detect that cheating, in some Claude Code runs.
  That was a research model trained to reward-hack, not a released one.

The guard does not assume intent. It checks the diff, because a removed assert does the same
damage whatever the reason.
