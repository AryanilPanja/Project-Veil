# veil agent-guard

Hooks for Claude Code that keep a coding agent away from veil's secrets and flag edits that
make tests, checks or ML evaluation pass without the code working.

```bash
veil agent-guard install              # in the project; --warn asks instead of blocking
veil agent-guard review               # the same diff review, by hand or in CI (--json)
veil agent-guard uninstall
```

## What install changes

- `.claude/settings.json`: merges deny rules, the OS sandbox and four hooks into what is
  already there. Your own rules and hooks stay.
  - Sandbox: shell commands run sandboxed, with no unsandboxed escape
    (`allowUnsandboxedCommands: false`), network only to PyPI and GitHub, and no reads of
    `~/.ssh`, `~/.gnupg`, `~/.config/gh`, the Keychain or veil's config.
  - `disableBypassPermissionsMode`: the agent can't be switched to skip-all-permissions.
- `CLAUDE.md` and `AGENTS.md`: a short block between `<!-- veil:begin -->` and
  `<!-- veil:end -->`. It tells the agent that veil is active, that names and contact details
  may be pseudonyms to keep as they are, and not to ask for real ones, run veil, or read the
  clipboard. Re-installing replaces the block; the rest of the file is untouched.
- The hooks call the interpreter that ran `install` by absolute path, so they work when
  `veil` is not on PATH. If the pre-tool hook can't start, it blocks.

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

## Limits

- The sandbox is the hard boundary. The pre-tool hook matches commands and paths; a
  program can write files in ways no pattern list covers. The Stop review then sees the
  result in the diff.
- The review reads `git diff`. Changes outside the repository are seen only through the
  session log.
- A HIGH finding sends the agent back once. If you asked for the change (deleting a test on
  purpose), the second stop goes through and the notification stays.
- Claude Code only. Other agents can run `veil agent-guard review` in CI.

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
