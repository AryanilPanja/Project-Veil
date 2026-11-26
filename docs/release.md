# Releasing and distributing veil

Current state: no releases. People install from a git clone with `uv sync`. Plan, in order;
each step works without the later ones.

## 1. One Python package for Linux and macOS

- Ship one package (`project-veil` in `pyproject.toml`), with a `veil` command, from one tag.
- Platform-only dependencies carry markers: `secretstorage` and `jeepney` install on Linux only.
  The macOS backends use ctypes, so a Mac install needs nothing extra.
- The compiled dependencies (`pyrage`, `pyahocorasick`, `pydantic-core`) publish wheels for
  Linux x86_64/arm64 and macOS arm64/x86_64, so no compiler is needed for a normal install.
- Install command in the README: `uv tool install project-veil` (or `pipx install project-veil`).
  Both give veil its own environment and put `veil` on PATH.

## 2. A release workflow in GitHub Actions

- Trigger: pushing a tag `vX.Y.Z`. The tag must match `version` in `pyproject.toml`; the job
  fails otherwise.
- Jobs:
  1. Test on `ubuntu-latest` and `macos-latest` (the CI matrix).
  2. Build: `uv build` makes the sdist and one pure-Python wheel. Set `SOURCE_DATE_EPOCH` to
     the tag's commit time so a rebuild gives the same bytes.
  3. Attest: `actions/attest-build-provenance` signs a provenance statement for both files
     (Sigstore, no key to manage). Users check with `gh attestation verify <file> --repo ...`.
  4. SBOM: generate a CycloneDX SBOM from `uv.lock` and attach it to the GitHub release.
  5. Publish to PyPI with Trusted Publishing (OIDC): no API token is stored anywhere. Run it in
     a GitHub environment named `pypi` that needs a maintainer's approval.
  6. GitHub release with the notes for that version from `CHANGELOG.md`, the two files, the
     SBOM and the attestation bundle.
- Pin every action to a full commit SHA, with the version in a comment. Dependabot updates
  the SHAs and `uv.lock` weekly.
- Workflow `permissions:` default to `contents: read`; only the publish job gets
  `id-token: write` and `attestations: write`.

## 3. Versions and notes

- SemVer. While the version starts with 0, a minor bump may change the persona format or the
  CLI; say so in the notes.
- `CHANGELOG.md` uses Keep a Changelog headings (Added, Changed, Fixed, Security).
- A persona format change ships with a migration in `veil persona import` and a note.

## 4. Homebrew (macOS), after PyPI

- A tap (`VA24d/homebrew-veil`) with a formula built by `brew update-python-resources`.
- `pyrage` builds from source under Homebrew's rules and needs Rust at build time; check the
  formula's build time on a clean Mac before announcing it.
- Until then, `uv tool install` is the macOS install path.

## 5. Linux packages, later

- Fedora COPR (the upstream author's platform), then an AUR package. Both can wrap the PyPI
  sdist.

## 6. A signed macOS app, only if needed

Needed for: a menu-bar ON/OFF switch, global hotkeys without Shortcuts.app, and
sanitize-then-paste (synthetic key presses need the Accessibility permission, which macOS
grants to a signed app, not to a Python interpreter).

- Apple Developer ID ($99 a year), hardened runtime, notarization with `notarytool`, stapled
  ticket.
- A small Swift shell that calls the same `veil` package; the engine stays in Python.
- Sign and notarize in CI from an environment that holds the certificate; never on a laptop.

## Checklist for one release

- [ ] `CHANGELOG.md` has the version and date.
- [ ] `version` in `pyproject.toml` bumped; `uv lock` run.
- [ ] Full suite green on Linux and macOS.
- [ ] Tag `vX.Y.Z` pushed; the workflow published to PyPI after approval.
- [ ] `uv tool install project-veil==X.Y.Z` works on a clean Mac and a clean Linux box.
- [ ] `veil --version` prints the attribution lines (GPL-3.0 section 7(b), see NOTICE).
