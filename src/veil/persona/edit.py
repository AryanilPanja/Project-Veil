"""`veil persona edit`: change the encrypted persona in a hardened editor (ADR-0025 §7, §8).

HUMAN-ONLY. Agents must never run this command: it shows real values on screen.

Flow:
1. require a terminal; take the store lock (a second edit or import gets exit 6);
2. decrypt in memory; write the YAML, without its canary, into a fresh session dir inside the
   validated tmpfs runtime dir (`$XDG_RUNTIME_DIR/veil/edit-*`, 0700; the file is 0600);
3. launch the editor hardened so it leaves nothing behind on disk: no swap, undo, backup,
   shada/viminfo, history or plugins; TMPDIR, the XDG state/cache/data dirs and the working
   directory all point into the session dir;
4. unchanged → nothing saved. Valid → re-insert the same canary, encrypt, verify, replace
   (+ `.bak`). Invalid → report by field path; nothing saved (T13 adds re-open / keep-draft);
5. always: overwrite and remove everything in the session dir.

Plaintext is only ever on tmpfs, and only while the editor runs. A hard crash of veil itself
(`os._exit` in the crash hooks skips `finally`) can leave a session dir behind on tmpfs; T13
adds recovery for that. tmpfs is cleared at logout/reboot anyway.
"""

import os
import shlex
import shutil
import subprocess
import tempfile
from collections.abc import Callable, Mapping
from dataclasses import dataclass, field
from enum import StrEnum
from pathlib import Path

from veil import fsutil, paths, ui
from veil.crypto.keystore import KeyStore
from veil.errors import UnsafeEnvironment, ValidationFailed, VeilError
from veil.exitcodes import ExitCode
from veil.persona import canary
from veil.persona.check import check_bytes
from veil.persona.report import render_text
from veil.persona.store import Payload, PersonaStore

SESSION_PREFIX = "edit-"
FILE_NAME = "persona.yaml"
MAX_EDITED_BYTES = 1024 * 1024

_VIM_SETTINGS = (
    "setlocal noundofile nobackup nowritebackup noswapfile"
    " | set undodir={d} directory={d} backupdir={d} viminfo= shada="
)


class EditorKind(StrEnum):
    VIM = "vim"  # vim, nvim, vi (when it is vim)
    EMACS = "emacs"
    NANO = "nano"
    UNKNOWN = "unknown"


# Editors that keep buffers in a long-running server or sync/restore sessions on their own:
# the file would outlive the session dir. Refused unless --allow-unknown-editor.
REFUSED = frozenset(
    {
        "emacsclient",
        "code",
        "code-insiders",
        "codium",
        "cursor",
        "zed",
        "zeditor",
        "subl",
        "windsurf",
    }
)
_KINDS = {
    "vim": EditorKind.VIM,
    "nvim": EditorKind.VIM,
    "vi": EditorKind.VIM,  # only if it resolves to vim/nvim (checked below)
    "vim.basic": EditorKind.VIM,
    "vim.tiny": EditorKind.VIM,
    "emacs": EditorKind.EMACS,
    "nano": EditorKind.NANO,
}


@dataclass(frozen=True)
class EditorCommand:
    argv: list[str]
    env: dict[str, str] = field(repr=False)
    kind: EditorKind


@dataclass(frozen=True)
class EditResult:
    changed: bool
    saved: bool
    warnings: int


Runner = Callable[[EditorCommand, Path], int]


# ── editor selection and hardening ────────────────────────────────────────────


def editor_command(
    editor: str | None,
    file: Path,
    session: Path,
    *,
    allow_unknown: bool = False,
    base_env: Mapping[str, str] | None = None,
) -> EditorCommand:
    """Build the hardened command line for `editor` (the $VISUAL/$EDITOR value) on `file`."""
    words = shlex.split(editor) if editor and editor.strip() else ["nvim"]
    name = Path(words[0]).name
    if name in REFUSED and not allow_unknown:
        raise UnsafeEnvironment(
            f"refusing editor '{name}': it keeps files outside the private session "
            "(use --allow-unknown-editor to override)"
        )
    kind = _KINDS.get(name, EditorKind.UNKNOWN)
    if name == "vi" and not _is_vim(words[0], base_env):
        kind = EditorKind.UNKNOWN  # busybox vi, nvi…: none of the vim hardening flags exist
    if kind is EditorKind.UNKNOWN and not allow_unknown:
        raise UnsafeEnvironment(
            f"refusing unknown editor '{name}': veil can only harden vim/nvim, emacs and nano "
            "(set EDITOR to one of them, or use --allow-unknown-editor)"
        )
    env = _session_env(base_env if base_env is not None else os.environ, session)
    target = str(file)
    if kind is EditorKind.VIM:
        argv = [
            *words,
            "--clean",
            "-n",
            "-i",
            "NONE",
            "-c",
            _VIM_SETTINGS.format(d=session),
            target,
        ]
    elif kind is EditorKind.EMACS:
        lisp = (
            "(setq make-backup-files nil auto-save-default nil create-lockfiles nil "
            "auto-save-list-file-prefix nil savehist-mode nil)"
        )
        argv = [*words, "-nw", "-Q", "--eval", lisp, target]
    elif kind is EditorKind.NANO:
        argv = [*words, "--ignorercfiles", "--nohelp", target]
    else:
        argv = [*words, target]
    return EditorCommand(argv=argv, env=env, kind=kind)


def _is_vim(command: str, env: Mapping[str, str] | None) -> bool:
    found = shutil.which(command, path=(env if env is not None else os.environ).get("PATH"))
    if found is None:
        return False
    if Path(found).resolve().name.startswith(("vim", "nvim")):
        return True
    try:  # e.g. Fedora's /usr/bin/vi is vim-minimal under its own name
        first = subprocess.run(  # noqa: S603 — fixed argv, no shell
            [found, "--version"], capture_output=True, text=True, timeout=5, check=False
        ).stdout.partition("\n")[0]
    except (OSError, subprocess.SubprocessError):
        return False
    return first.startswith(("VIM - Vi IMproved", "NVIM"))


def _session_env(base: Mapping[str, str], session: Path) -> dict[str, str]:
    """Everything an editor might write as a side effect lands in the session dir."""
    env = dict(base)
    for variable, sub in (
        ("TMPDIR", "tmp"),
        ("XDG_STATE_HOME", "state"),
        ("XDG_CACHE_HOME", "cache"),
        ("XDG_DATA_HOME", "data"),
    ):
        path = session / sub
        path.mkdir(mode=0o700, exist_ok=True)
        env[variable] = str(path)
    # Never let a GUI editor hand the file to an already-running instance.
    env.pop("NVIM", None)
    env.pop("NVIM_LISTEN_ADDRESS", None)
    return env


def chosen_editor(env: Mapping[str, str] | None = None) -> str | None:
    env = os.environ if env is None else env
    return env.get("VISUAL") or env.get("EDITOR") or None


def run_editor(command: EditorCommand, session: Path) -> int:
    """Run the editor attached to the terminal, with the session dir as working directory."""
    executable = shutil.which(command.argv[0], path=command.env.get("PATH"))
    if executable is None:
        raise VeilError(
            f"editor '{Path(command.argv[0]).name}' not found", exit_code=ExitCode.USAGE
        )
    completed = subprocess.run(  # noqa: S603 — argv list, no shell
        [executable, *command.argv[1:]], env=command.env, cwd=session, check=False
    )
    return completed.returncode


# ── the edit session ──────────────────────────────────────────────────────────


def edit_persona(
    *,
    keystore: KeyStore,
    store: PersonaStore,
    ask_passphrase: Callable[[], str] | None,
    allow_unknown_editor: bool = False,
    editor: str | None = None,
    runner: Runner = run_editor,
    read: paths.TextReader = paths._read_text,
) -> EditResult:
    ui.require_tty("veil persona edit")
    runtime = fsutil.ensure_private_dir(paths.runtime_dir(read), "the veil runtime directory")
    if paths.swap_status(read).at_risk:
        ui.err(
            "veil: warning: unencrypted swap is active; the decrypted persona could be paged "
            "to disk while you edit (plan P0.8)"
        )

    with store.lock():
        identity = keystore.load(ask_passphrase)
        current = store.load(identity)
        marker = current.canary  # store.load guarantees exactly one canary
        if marker is None:
            raise ValidationFailed("the encrypted persona has no canary")
        shown = canary.remove(current.data.decode("utf-8")).encode("utf-8")

        session = Path(tempfile.mkdtemp(prefix=SESSION_PREFIX, dir=runtime))
        try:
            file = session / FILE_NAME
            _write_new(file, shown)
            command = editor_command(
                editor if editor is not None else chosen_editor(),
                file,
                session,
                allow_unknown=allow_unknown_editor,
            )
            status = runner(command, session)
            if status != 0:
                raise VeilError(
                    f"the editor exited with status {status}; nothing was saved",
                    exit_code=ExitCode.ABORTED,
                )
            edited = fsutil.read_private(file, MAX_EDITED_BYTES, "the edited persona")
        finally:
            wipe_session(session)

        if edited == shown:
            ui.err("veil: no changes; nothing saved")
            return EditResult(changed=False, saved=False, warnings=0)
        report = check_bytes(edited)
        if report.errors:
            ui.out(render_text(report))
            raise ValidationFailed(
                f"the edited persona has {len(report.errors)} error(s); nothing was saved"
            )
        text = edited.decode("utf-8")
        payload = Payload(canary.insert(text, marker).encode("utf-8"))
        store.save(payload, identity, recipient=keystore.recipient())
    if report.findings:
        ui.out(render_text(report))
    return EditResult(changed=True, saved=True, warnings=len(report.warnings))


def _write_new(path: Path, data: bytes) -> None:
    fd = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW | os.O_CLOEXEC, 0o600)
    try:
        view = memoryview(data)
        while view:
            view = view[os.write(fd, view) :]
    finally:
        os.close(fd)


def wipe_session(session: Path) -> None:
    """Overwrite and remove every file under `session`, then the directories. Best effort."""
    if not session.exists() or session.is_symlink():
        return
    for root, dirs, files in os.walk(session, topdown=False, followlinks=False):
        here = Path(root)
        for name in files:
            try:
                fsutil.secure_remove(here / name, "a session file")
            except VeilError:
                (here / name).unlink(missing_ok=True)
        for name in dirs:
            target = here / name
            if target.is_symlink():
                target.unlink(missing_ok=True)
            else:
                target.rmdir()
    session.rmdir()
