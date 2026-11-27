"""Project Veil: translate personal information into a consistent fake persona."""


def __getattr__(name: str) -> str:
    # Computed on first use: importlib.metadata costs ~20 ms at import, and every hotkey
    # invocation imports veil.
    if name == "__version__":
        from importlib.metadata import version

        return version("project-veil")
    raise AttributeError(name)
