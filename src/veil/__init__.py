"""Project Veil: translate personal information into a consistent fake persona."""

# GPL-3.0 section 7(b) attribution (see NOTICE): conveyed versions must keep it in --version.
ATTRIBUTION = (
    "Based on Project Veil by Aryanil Panja (https://github.com/AryanilPanja/Project-Veil).\n"
    "License: GPL-3.0-only. This is free software; see LICENSE and NOTICE."
)


def __getattr__(name: str) -> str:
    # Computed on first use: importlib.metadata costs ~20 ms at import, and every hotkey
    # invocation imports veil.
    if name == "__version__":
        from importlib.metadata import version

        return version("project-veil")
    raise AttributeError(name)
