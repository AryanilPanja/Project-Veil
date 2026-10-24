"""persona/edit.py (T12): hardened editor command, session dir on tmpfs, happy path, cleanup.

Never runs a real interactive editor: a fake runner edits the file in-process, a scripted
"editor" runs as a real subprocess, and real nvim runs headless when installed. Synthetic
persona and throwaway config/runtime dirs only.
"""

import os
import shutil
import stat
import subprocess
import sys
import textwrap
from pathlib import Path

import pytest

from tests.unit.test_check_cli import FIXTURE
from veil import cli, ui
from veil.crypto import age
from veil.crypto.keystore import SERVICE, USERNAME
from veil.errors import Busy, StorageError, UnsafeEnvironment, ValidationFailed, VeilError
from veil.exitcodes import ExitCode
from veil.persona import canary, edit
from veil.persona.store import STORE_FILE

# ── helpers ───────────────────────────────────────────────────────────────────


def mode(path: Path) -> int:
    return stat.S_IMODE(path.lstat().st_mode)


@pytest.fixture
def runtime(tmp_path, monkeypatch):
    """A private tmpfs-looking runtime dir, plus a /proc reader describing it."""
    base = tmp_path / "rt-edit"
    base.mkdir(mode=0o700)
    base.chmod(0o700)
    monkeypatch.setenv("XDG_RUNTIME_DIR", str(base))
    files = {
        "/proc/self/mountinfo": f"1 0 0:1 / / rw - ext4 x rw\n2 1 0:2 / {base} rw - tmpfs t rw\n",
        "/proc/swaps": "Filename Type Size Used Priority\n",
    }

    def read(path):
        if path not in files:
            raise FileNotFoundError(path)
        return files[path]

    return base, read, files


@pytest.fixture
def tty(monkeypatch):
    monkeypatch.setattr(ui, "_isatty", lambda _stream: True)


@pytest.fixture
def imported(veil_home, tmp_path, capsys):
    source = tmp_path / "draft.yaml"
    shutil.copyfile(FIXTURE, source)
    assert cli.main(["persona", "import", str(source)]) == ExitCode.OK
    capsys.readouterr()
    return veil_home


def identity_of(home):
    return age.parse_identity(home.ring.items[(SERVICE, USERNAME)])


def stored_text(home) -> str:
    return age.decrypt((home.config / STORE_FILE).read_bytes(), identity_of(home)).decode()


class FakeEditor:
    """Records what the editor would see, then applies `change` to the file."""

    def __init__(self, change=None, status: int = 0, raises: BaseException | None = None):
        self.change = change
        self.status = status
        self.raises = raises
        self.commands: list[edit.EditorCommand] = []
        self.seen: dict[str, object] = {}

    def __call__(self, command: edit.EditorCommand, session: Path) -> int:
        self.commands.append(command)
        file = Path(command.argv[-1])
        self.seen = {
            "text": file.read_text(encoding="utf-8"),
            "file_mode": mode(file),
            "session": session,
            "session_mode": mode(session),
            "parent": session.parent,
        }
        if self.raises is not None:
            raise self.raises
        if self.change is not None:
            self.change(file)
        return self.status


def replace(old: str, new: str):
    def apply(file: Path) -> None:
        text = file.read_text(encoding="utf-8")
        assert old in text
        file.write_text(text.replace(old, new, 1), encoding="utf-8")

    return apply


def run_edit(home, read, runner, **kwargs):
    from veil.crypto.keystore import KeyStore
    from veil.persona.store import PersonaStore

    return edit.edit_persona(
        keystore=KeyStore(home.config, timeout=2),
        store=PersonaStore(home.config),
        ask_passphrase=kwargs.pop("ask_passphrase", None),
        runner=runner,
        read=read,
        editor=kwargs.pop("editor", "nvim"),
        **kwargs,
    )


# ── editor command ────────────────────────────────────────────────────────────


class TestEditorCommand:
    @pytest.fixture
    def session(self, tmp_path):
        s = tmp_path / "edit-session"
        s.mkdir(mode=0o700)
        return s

    def test_default_is_hardened_nvim(self, session):
        file = session / "persona.yaml"
        cmd = edit.editor_command(None, file, session, base_env={"PATH": "/usr/bin"})
        assert cmd.kind is edit.EditorKind.VIM
        assert cmd.argv[:5] == ["nvim", "--clean", "-n", "-i", "NONE"]
        assert cmd.argv[-1] == str(file)
        settings = cmd.argv[cmd.argv.index("-c") + 1]
        for word in ("noundofile", "nobackup", "nowritebackup", "noswapfile", "shada=", "viminfo="):
            assert word in settings
        for option in ("undodir", "directory", "backupdir"):
            assert f"{option}={session}" in settings

    @pytest.mark.parametrize("value", ["", "   ", None])
    def test_blank_editor_falls_back_to_nvim(self, session, value):
        assert edit.editor_command(value, session / "f", session, base_env={}).argv[0] == "nvim"

    @pytest.mark.parametrize("value", ["vim", "/usr/bin/nvim", "nvim", "vim.basic", "vim.tiny"])
    def test_vim_family(self, session, value):
        cmd = edit.editor_command(value, session / "f", session, base_env={})
        assert cmd.kind is edit.EditorKind.VIM
        assert cmd.argv[0] == value
        assert "--clean" in cmd.argv

    def test_user_arguments_are_kept_and_quoting_respected(self, session):
        cmd = edit.editor_command('nvim -R "--cmd=set nu"', session / "f", session, base_env={})
        assert cmd.argv[:3] == ["nvim", "-R", "--cmd=set nu"]
        assert "--clean" in cmd.argv

    def test_emacs_hardening(self, session):
        cmd = edit.editor_command("emacs", session / "f", session, base_env={})
        assert cmd.kind is edit.EditorKind.EMACS
        assert "-Q" in cmd.argv
        assert "-nw" in cmd.argv
        lisp = cmd.argv[cmd.argv.index("--eval") + 1]
        for setting in ("make-backup-files nil", "auto-save-default nil", "create-lockfiles nil"):
            assert setting in lisp

    def test_nano_hardening(self, session):
        cmd = edit.editor_command("nano", session / "f", session, base_env={})
        assert cmd.kind is edit.EditorKind.NANO
        assert "--ignorercfiles" in cmd.argv  # no rc file → no search/position history files

    @pytest.mark.parametrize("name", sorted(edit.REFUSED))
    def test_refused_editors(self, session, name):
        with pytest.raises(UnsafeEnvironment, match="refusing editor") as info:
            edit.editor_command(name, session / "f", session, base_env={})
        assert info.value.exit_code == ExitCode.UNSAFE_ENVIRONMENT

    @pytest.mark.parametrize("name", ["code --wait", "/opt/cursor/cursor", "emacsclient -t"])
    def test_refused_editors_with_paths_and_args(self, session, name):
        with pytest.raises(UnsafeEnvironment):
            edit.editor_command(name, session / "f", session, base_env={})

    @pytest.mark.parametrize("name", ["gedit", "kate", "micro", "helix", "hx", "ed", "joe"])
    def test_unknown_editors_refused(self, session, name):
        with pytest.raises(UnsafeEnvironment, match="unknown editor"):
            edit.editor_command(name, session / "f", session, base_env={})

    @pytest.mark.parametrize("name", ["kate", "code --wait"])
    def test_override_runs_editor_plainly(self, session, name):
        cmd = edit.editor_command(name, session / "f", session, allow_unknown=True, base_env={})
        assert cmd.kind is edit.EditorKind.UNKNOWN
        assert cmd.argv[-1] == str(session / "f")
        assert "--clean" not in cmd.argv

    def test_env_redirects_side_effects_into_session(self, session):
        base = {"PATH": "/usr/bin", "HOME": "/home/x", "NVIM": "/run/nvim.sock", "LANG": "C.UTF-8"}
        cmd = edit.editor_command("nvim", session / "f", session, base_env=base)
        for variable, sub in (
            ("TMPDIR", "tmp"),
            ("XDG_STATE_HOME", "state"),
            ("XDG_CACHE_HOME", "cache"),
            ("XDG_DATA_HOME", "data"),
        ):
            assert cmd.env[variable] == str(session / sub)
            assert (session / sub).is_dir()
            assert mode(session / sub) == 0o700
        assert "NVIM" not in cmd.env
        assert cmd.env["LANG"] == "C.UTF-8"
        assert base["NVIM"] == "/run/nvim.sock"  # caller's mapping untouched

    def test_env_not_in_repr(self, session):
        cmd = edit.editor_command("nvim", session / "f", session, base_env={"SECRET_TOKEN": "x1"})
        assert "SECRET_TOKEN" not in repr(cmd)

    def test_error_names_editor_only(self, session):
        with pytest.raises(UnsafeEnvironment) as info:
            edit.editor_command("/home/jane/bin/gedit", session / "f", session, base_env={})
        assert "jane" not in str(info.value)
        assert "'gedit'" in str(info.value)


class TestViDetection:
    def fake_vi(self, tmp_path, version_line: str) -> dict[str, str]:
        bindir = tmp_path / "bin"
        bindir.mkdir(exist_ok=True)
        vi = bindir / "vi"
        vi.write_text(f"#!/bin/sh\necho '{version_line}'\n")
        vi.chmod(0o755)
        return {"PATH": str(bindir)}

    def test_vim_minimal_named_vi_is_hardened(self, tmp_path):
        env = self.fake_vi(tmp_path, "VIM - Vi IMproved 9.2")
        cmd = edit.editor_command("vi", tmp_path / "f", tmp_path, base_env=env)
        assert cmd.kind is edit.EditorKind.VIM

    def test_nvim_named_vi_is_hardened(self, tmp_path):
        env = self.fake_vi(tmp_path, "NVIM v0.11.0")
        assert edit.editor_command("vi", tmp_path / "f", tmp_path, base_env=env).kind is (
            edit.EditorKind.VIM
        )

    @pytest.mark.parametrize("line", ["BusyBox v1.36", "nvi 1.81", ""])
    def test_other_vi_is_refused(self, tmp_path, line):
        env = self.fake_vi(tmp_path, line)
        with pytest.raises(UnsafeEnvironment, match="unknown editor"):
            edit.editor_command("vi", tmp_path / "f", tmp_path, base_env=env)

    def test_vi_symlink_to_vim_binary(self, tmp_path):
        bindir = tmp_path / "bin"
        bindir.mkdir()
        target = bindir / "vim"
        target.write_text("#!/bin/sh\nexit 0\n")
        target.chmod(0o755)
        (bindir / "vi").symlink_to(target)
        cmd = edit.editor_command("vi", tmp_path / "f", tmp_path, base_env={"PATH": str(bindir)})
        assert cmd.kind is edit.EditorKind.VIM

    def test_missing_vi(self, tmp_path):
        with pytest.raises(UnsafeEnvironment):
            edit.editor_command("vi", tmp_path / "f", tmp_path, base_env={"PATH": str(tmp_path)})


class TestChosenEditor:
    @pytest.mark.parametrize(
        ("env", "expected"),
        [
            ({"VISUAL": "vim", "EDITOR": "nano"}, "vim"),
            ({"EDITOR": "nano"}, "nano"),
            ({"VISUAL": "", "EDITOR": "emacs"}, "emacs"),
            ({}, None),
        ],
    )
    def test_visual_then_editor(self, env, expected):
        assert edit.chosen_editor(env) == expected


# ── the edit session ──────────────────────────────────────────────────────────


class TestHappyPath:
    def test_valid_change_is_saved_with_same_canary(self, imported, runtime, tty):
        _, read, _ = runtime
        before = stored_text(imported)
        old_canary = canary.find_all(before)[0]
        result = run_edit(
            imported, read, FakeEditor(replace("fidelity: semantic", "fidelity: loose"))
        )
        assert result == edit.EditResult(changed=True, saved=True, warnings=0)
        after = stored_text(imported)
        assert "fidelity: loose" in after
        assert canary.find_all(after) == [old_canary, old_canary]
        assert canary.remove(after).replace("loose", "semantic") == canary.remove(before)

    def test_backup_holds_previous_version(self, imported, runtime, tty):
        _, read, _ = runtime
        old = (imported.config / STORE_FILE).read_bytes()
        run_edit(imported, read, FakeEditor(replace("fidelity: semantic", "fidelity: loose")))
        assert (imported.config / (STORE_FILE + ".bak")).read_bytes() == old

    def test_editor_sees_private_file_without_canary(self, imported, runtime, tty):
        base, read, _ = runtime
        editor = FakeEditor()
        run_edit(imported, read, editor)
        assert "VEIL-CANARY" not in editor.seen["text"]
        assert "veil_canary" not in editor.seen["text"]
        assert editor.seen["file_mode"] == 0o600
        assert editor.seen["session_mode"] == 0o700
        assert editor.seen["parent"] == base / "veil"
        assert editor.seen["session"].name.startswith(edit.SESSION_PREFIX)

    def test_session_is_wiped_afterwards(self, imported, runtime, tty):
        base, read, _ = runtime
        editor = FakeEditor(replace("fidelity: semantic", "fidelity: loose"))
        run_edit(imported, read, editor)
        assert not editor.seen["session"].exists()
        assert list((base / "veil").iterdir()) == []
        assert mode(base / "veil") == 0o700

    def test_no_changes_saves_nothing(self, imported, runtime, tty, capsys):
        _, read, _ = runtime
        before = (imported.config / STORE_FILE).read_bytes()
        result = run_edit(imported, read, FakeEditor())
        assert result == edit.EditResult(changed=False, saved=False, warnings=0)
        assert (imported.config / STORE_FILE).read_bytes() == before
        assert "no changes" in capsys.readouterr().err

    def test_unicode_edit(self, imported, runtime, tty):
        _, read, _ = runtime
        change = replace("never_translate:", "never_translate:\n  - নমুনা শব্দ")
        if "never_translate:" not in canary.remove(stored_text(imported)):
            change = replace(
                "fidelity: semantic", 'fidelity: semantic\nnever_translate: ["নমুনা শব্দ"]'
            )
        run_edit(imported, read, FakeEditor(change))
        assert "নমুনা শব্দ" in stored_text(imported)

    def test_new_warning_reported_value_free(self, imported, runtime, tty, capsys):
        _, read, _ = runtime
        editor = FakeEditor(replace("{ real: Jane, fake: Alex }", "{ real: Jo, fake: Al2 }"))
        result = run_edit(imported, read, editor)
        assert result.saved
        out = capsys.readouterr().out
        assert "W101" in out
        for value in ("Jo,", "Al2", "Jane", "Alex"):
            assert value not in out

    def test_passphrase_mode(self, veil_home, runtime, tty, tmp_path, monkeypatch, capsys):
        _, read, _ = runtime
        source = tmp_path / "draft.yaml"
        shutil.copyfile(FIXTURE, source)
        secrets = ["correct horse battery"] * 2
        monkeypatch.setattr(ui, "prompt_secret", lambda _p: secrets.pop(0))
        cli.main(["persona", "import", "--key-backend", "file", str(source)])
        asked: list[int] = []

        def ask():
            asked.append(1)
            return "correct horse battery"

        result = run_edit(
            veil_home,
            read,
            FakeEditor(replace("fidelity: semantic", "fidelity: max")),
            ask_passphrase=ask,
        )
        assert result.saved
        assert asked == [1]

    def test_swap_warning(self, imported, runtime, tty, capsys):
        _, read, files = runtime
        files["/proc/swaps"] += "/dev/sda2 partition 1 0 -2\n"
        run_edit(imported, read, FakeEditor())
        assert "unencrypted swap" in capsys.readouterr().err


# ── refusals and failures (nothing saved, nothing left behind) ────────────────


class TestFailuresLeaveNoTrace:
    @pytest.fixture
    def setup(self, imported, runtime, tty):
        base, read, _files = runtime
        before = (imported.config / STORE_FILE).read_bytes()

        def unchanged():
            assert (imported.config / STORE_FILE).read_bytes() == before
            leftover = list((base / "veil").iterdir()) if (base / "veil").exists() else []
            assert leftover == []

        return imported, read, unchanged

    def test_invalid_edit_not_saved(self, setup, capsys):
        home, read, unchanged = setup
        broken = replace("fidelity: semantic", "fidelity: semantic\nnot_a_field: 1")
        with pytest.raises(ValidationFailed, match="nothing was saved") as info:
            run_edit(home, read, FakeEditor(broken))
        assert info.value.exit_code == ExitCode.FINDINGS
        assert "E003" in capsys.readouterr().out
        unchanged()

    def test_yaml_syntax_error_not_saved(self, setup):
        home, read, unchanged = setup
        with pytest.raises(ValidationFailed):
            run_edit(home, read, FakeEditor(lambda f: f.write_text("version: [\n")))
        unchanged()

    def test_editor_failure_status(self, setup):
        home, read, unchanged = setup
        editor = FakeEditor(replace("fidelity: semantic", "fidelity: loose"), status=1)
        with pytest.raises(VeilError, match="exited with status 1") as info:
            run_edit(home, read, editor)
        assert info.value.exit_code == ExitCode.ABORTED
        unchanged()

    def test_interrupt_during_editing(self, setup):
        home, read, unchanged = setup
        with pytest.raises(KeyboardInterrupt):
            run_edit(home, read, FakeEditor(raises=KeyboardInterrupt()))
        unchanged()

    def test_editor_deletes_the_file(self, setup):
        home, read, unchanged = setup
        with pytest.raises(StorageError):
            run_edit(home, read, FakeEditor(lambda f: f.unlink()))
        unchanged()

    def test_editor_replaces_file_with_symlink(self, setup, tmp_path):
        home, read, unchanged = setup
        outside = tmp_path / "outside.yaml"
        outside.write_text("version: 1\n")

        def swap(f: Path) -> None:
            f.unlink()
            f.symlink_to(outside)

        with pytest.raises(UnsafeEnvironment):
            run_edit(home, read, FakeEditor(swap))
        assert outside.read_text() == "version: 1\n"
        unchanged()

    def test_editor_leaves_extra_files_they_are_wiped(self, setup, runtime):
        home, read, unchanged = setup

        def litter(f: Path) -> None:
            (f.parent / ".persona.yaml.swp").write_text("copy")
            (f.parent / "state" / "nvim").mkdir(parents=True)
            (f.parent / "state" / "nvim" / "undo").write_text("copy")

        run_edit(home, read, FakeEditor(litter))
        unchanged()

    def test_refused_editor(self, setup):
        home, read, unchanged = setup
        with pytest.raises(UnsafeEnvironment, match="refusing editor"):
            run_edit(home, read, FakeEditor(), editor="code --wait")
        unchanged()

    def test_no_terminal_refused_before_decrypting(self, imported, runtime, monkeypatch):
        _, read, _ = runtime
        imported.ring.calls.clear()
        with pytest.raises(UnsafeEnvironment, match="interactive terminal"):
            run_edit(imported, read, FakeEditor())
        assert imported.ring.calls == []

    def test_runtime_dir_not_tmpfs_refused_before_decrypting(self, imported, runtime, tty):
        base, read, files = runtime
        files["/proc/self/mountinfo"] = (
            f"1 0 0:1 / / rw - ext4 x rw\n2 1 0:2 / {base} rw - ext4 t rw\n"
        )
        imported.ring.calls.clear()
        with pytest.raises(UnsafeEnvironment, match="not in memory"):
            run_edit(imported, read, FakeEditor())
        assert imported.ring.calls == []
        assert not (base / "veil").exists()

    def test_runtime_veil_dir_symlink_refused(self, imported, runtime, tty, tmp_path):
        base, read, _ = runtime
        elsewhere = tmp_path / "disk"
        elsewhere.mkdir(mode=0o700)
        (base / "veil").symlink_to(elsewhere)
        with pytest.raises(UnsafeEnvironment, match="symbolic link"):
            run_edit(imported, read, FakeEditor())
        assert list(elsewhere.iterdir()) == []

    def test_lock_held(self, imported, runtime, tty):
        from veil.persona.store import PersonaStore

        _, read, _ = runtime
        with PersonaStore(imported.config).lock(), pytest.raises(Busy):
            run_edit(imported, read, FakeEditor())

    def test_nothing_imported(self, veil_home, runtime, tty):
        _, read, _ = runtime
        with pytest.raises(VeilError) as info:
            run_edit(veil_home, read, FakeEditor())
        assert info.value.exit_code == ExitCode.KEY_UNAVAILABLE


class TestWipeSession:
    def test_nested_files_and_symlinks(self, tmp_path):
        session = tmp_path / "edit-x"
        (session / "a" / "b").mkdir(parents=True)
        (session / "a" / "b" / "f").write_text("secret")
        victim = tmp_path / "victim"
        victim.write_text("keep")
        (session / "link").symlink_to(victim)
        (session / "dirlink").symlink_to(tmp_path)
        edit.wipe_session(session)
        assert not session.exists()
        assert victim.read_text() == "keep"

    def test_missing_session_is_fine(self, tmp_path):
        edit.wipe_session(tmp_path / "gone")

    def test_symlinked_session_is_not_followed(self, tmp_path):
        real = tmp_path / "real"
        real.mkdir()
        (real / "f").write_text("keep")
        link = tmp_path / "edit-link"
        link.symlink_to(real)
        edit.wipe_session(link)
        assert (real / "f").read_text() == "keep"


# ── through the CLI with a real (scripted) editor process ─────────────────────


SCRIPT = textwrap.dedent(
    """\
    #!{python}
    import os, sys, pathlib
    path = pathlib.Path(sys.argv[-1])
    log = pathlib.Path({log!r})
    log.write_text("\\n".join([
        os.getcwd(), os.environ["TMPDIR"], os.environ["XDG_STATE_HOME"], str(path.parent)
    ]))
    path.write_text(path.read_text().replace("fidelity: semantic", "fidelity: loose"))
    """
)


@pytest.fixture
def scripted_editor(tmp_path, monkeypatch):
    log = tmp_path / "editor-log.txt"
    script = tmp_path / "fake-editor"
    script.write_text(SCRIPT.format(python=sys.executable, log=str(log)))
    script.chmod(0o755)
    monkeypatch.setenv("EDITOR", str(script))
    monkeypatch.delenv("VISUAL", raising=False)
    return log


@pytest.fixture
def cli_runtime(runtime, monkeypatch):
    _, read, _ = runtime
    real = edit.edit_persona
    monkeypatch.setattr(edit, "edit_persona", lambda **kw: real(read=read, **kw))
    return runtime


class TestCli:
    def test_unknown_editor_refused_without_flag(
        self, imported, cli_runtime, tty, scripted_editor, capsys
    ):
        assert cli.main(["persona", "edit"]) == ExitCode.UNSAFE_ENVIRONMENT
        assert "--allow-unknown-editor" in capsys.readouterr().err

    def test_scripted_editor_runs_in_session(
        self, imported, cli_runtime, tty, scripted_editor, capsys
    ):
        base, _, _ = cli_runtime
        assert cli.main(["persona", "edit", "--allow-unknown-editor"]) == ExitCode.OK
        out = capsys.readouterr().out
        assert "persona saved and encrypted" in out
        cwd, tmpdir, state, parent = scripted_editor.read_text().splitlines()
        assert cwd == parent
        assert Path(tmpdir) == Path(parent) / "tmp"
        assert state == f"{parent}/state"
        assert Path(parent).parent == base / "veil"
        assert not Path(parent).exists()
        assert "fidelity: loose" in stored_text(imported)

    def test_no_terminal(self, imported, cli_runtime, scripted_editor, capsys):
        assert (
            cli.main(["persona", "edit", "--allow-unknown-editor"]) == ExitCode.UNSAFE_ENVIRONMENT
        )
        assert not scripted_editor.exists()

    def test_editor_not_found(self, imported, cli_runtime, tty, monkeypatch, capsys):
        monkeypatch.setenv("EDITOR", "/nonexistent/bin/editor-xyz")
        assert cli.main(["persona", "edit", "--allow-unknown-editor"]) == ExitCode.USAGE
        assert "not found" in capsys.readouterr().err


@pytest.mark.skipif(shutil.which("nvim") is None, reason="nvim not installed")
class TestRealNvimHeadless:
    """Runs the exact hardened nvim command (plus headless edit commands) and checks that nvim
    wrote nothing outside the session: no undo, swap, shada or log files in the sandbox home."""

    def test_no_files_outside_session(self, imported, runtime, tty):
        _, read, _ = runtime
        home = Path(os.environ["HOME"])
        home.mkdir(parents=True, exist_ok=True)

        def headless(command: edit.EditorCommand, session: Path) -> int:
            argv = [
                *command.argv[:-1],
                "--headless",
                "-c",
                "%s/fidelity: semantic/fidelity: loose/",
                "-c",
                "wq",
                command.argv[-1],
            ]
            env = {**command.env, "HOME": str(home)}
            return subprocess.run(argv, env=env, cwd=session, check=False, timeout=60).returncode

        before = sorted(p for p in home.rglob("*"))
        result = run_edit(imported, read, headless)
        assert result.saved
        assert "fidelity: loose" in stored_text(imported)
        assert sorted(p for p in home.rglob("*")) == before
