"""Size limits shared by the YAML loader and the store (no heavy imports: used on the warm path)."""

MAX_BYTES = 1024 * 1024  # a persona document: 1 MiB of UTF-8 YAML
