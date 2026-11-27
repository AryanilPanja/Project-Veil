"""Field paths like `education[0].advisor.forms`: the only way findings and logs refer to data."""


def child(base: str, name: str) -> str:
    return f"{base}.{name}" if base else name


def item(base: str, index: int) -> str:
    return f"{base}[{index}]"
