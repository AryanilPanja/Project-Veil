"""Safe YAML loading for persona files.

Differences from `yaml.safe_load`, each closing a way to silently corrupt or leak a persona:

- Duplicate keys are an error (E002). PyYAML would silently keep the last one.
- Scalars stay text unless they are `true`/`false` or null. YAML 1.1 would turn a roll number
  `0123` into 83, `no` into False, `2001-03-14` into a date and `1e3` into a float.
- Anchors, aliases and merge keys are rejected: a persona never needs them, and aliases allow
  exponential-expansion ("billion laughs") input.
- Only one document, a mapping at the top, at most MAX_BYTES of UTF-8.
- Errors carry a code, a fixed problem description and a line/column, never source text:
  PyYAML's own messages quote the offending line, which holds persona values.
"""

import re
from typing import Any

import yaml
from yaml.composer import ComposerError
from yaml.constructor import ConstructorError
from yaml.events import AliasEvent, CollectionStartEvent, ScalarEvent
from yaml.nodes import MappingNode, Node, ScalarNode
from yaml.parser import ParserError
from yaml.reader import ReaderError
from yaml.scanner import ScannerError

from veil.errors import PersonaFormatError
from veil.persona.limits import MAX_BYTES

SYNTAX = "E001"
DUPLICATE_KEY = "E002"
SHAPE = "E003"
MAX_DEPTH = 32  # the template is about 6 levels deep

_BOOL = re.compile(r"^(?:true|True|TRUE|false|False|FALSE)$")
_NULL = re.compile(r"^(?:~|null|Null|NULL|)$")
_BOOL_TAG = "tag:yaml.org,2002:bool"
_NULL_TAG = "tag:yaml.org,2002:null"
_ALLOWED_TAGS = frozenset(
    {
        "tag:yaml.org,2002:str",
        "tag:yaml.org,2002:seq",
        "tag:yaml.org,2002:map",
        _BOOL_TAG,
        _NULL_TAG,
    }
)


class _Rejected(yaml.MarkedYAMLError):
    """Raised by the loader for constructs veil refuses; carries a code and a fixed problem."""

    def __init__(self, code: str, problem: str, mark: yaml.Mark | None) -> None:
        super().__init__(problem=problem, problem_mark=mark)
        self.code = code


class _PersonaLoader(yaml.SafeLoader):
    # An empty table: none of SafeLoader's implicit resolvers (int, float, timestamp, YAML 1.1
    # bools, merge, value) apply. Only the two below are registered.
    yaml_implicit_resolvers: dict[Any, Any] = {}  # noqa: RUF012 - PyYAML class-level registry

    def compose_node(self, parent: Node | None, index: Any) -> Node | None:
        event = self.peek_event()
        if isinstance(event, AliasEvent) or (
            isinstance(event, (ScalarEvent, CollectionStartEvent)) and event.anchor is not None
        ):
            raise _Rejected(SYNTAX, "anchors and aliases are not allowed", event.start_mark)
        # A persona is a few levels deep; a hostile document nested thousands deep would
        # otherwise end in a RecursionError (a traceback instead of a value-free E001).
        depth = getattr(self, "_veil_depth", 0)
        if depth >= MAX_DEPTH:
            raise _Rejected(SYNTAX, "nested too deeply", event.start_mark)
        self._veil_depth = depth + 1
        try:
            return super().compose_node(parent, index)
        finally:
            self._veil_depth = depth

    def construct_object(self, node: Node, deep: bool = False) -> Any:
        # Explicit tags must not smuggle in other types (`!!int 1`, `!!timestamp`, `!!binary`,
        # `!!set`, `!!python/...`), and `!!bool yes` / `!!null x` must not bypass the regexes.
        tag = node.tag
        scalar = isinstance(node, ScalarNode)
        if (
            tag not in _ALLOWED_TAGS
            # `!!bool []` / `!!null {}`: a collection under a scalar tag (node.value is a list)
            or (tag in (_BOOL_TAG, _NULL_TAG) and not scalar)
            or (tag == _BOOL_TAG and not _BOOL.match(node.value))
            or (tag == _NULL_TAG and not _NULL.match(node.value))
        ):
            raise _Rejected(SYNTAX, "unsupported value or tag", node.start_mark)
        return super().construct_object(node, deep=deep)

    def construct_mapping(self, node: MappingNode, deep: bool = False) -> dict[Any, Any]:
        seen: set[str] = set()
        for key_node, _value_node in node.value:
            key = self.construct_object(key_node, deep=deep)
            if not isinstance(key, str):
                raise _Rejected(SYNTAX, "keys must be text", key_node.start_mark)
            if key in seen:
                raise _Rejected(DUPLICATE_KEY, "duplicate key", key_node.start_mark)
            seen.add(key)
        return super().construct_mapping(node, deep=deep)


_PersonaLoader.add_implicit_resolver(_BOOL_TAG, _BOOL, list("tTfF"))
_PersonaLoader.add_implicit_resolver(_NULL_TAG, _NULL, ["~", "n", "N", ""])


def load_yaml(source: str | bytes) -> dict[str, Any]:
    """Parse a persona document. Raises PersonaFormatError (value-free) on any problem."""
    text = _decode(source)
    loader: _PersonaLoader | None = None
    error: PersonaFormatError | None = None
    data: Any = None
    try:
        # The reader validates characters while the loader is being built, so construction
        # must be inside the try as well.
        loader = _PersonaLoader(text)
        data = loader.get_single_data()
    except _Rejected as exc:
        error = _format_error(exc.code, exc.problem or "invalid YAML", exc.problem_mark)
    except yaml.YAMLError as exc:
        error = _translate(exc)
    except RecursionError:  # a second line of defence behind MAX_DEPTH
        error = _format_error(SYNTAX, "nested too deeply", None)
    finally:
        if loader is not None:
            loader.dispose()
    if error is not None:
        # Raised outside the except block on purpose: no __cause__ or __context__ link to the
        # PyYAML exception, whose message quotes source lines and whose marks hold the whole
        # plaintext document.
        raise error
    if data is None:
        raise PersonaFormatError(SHAPE, "the file is empty; expected a mapping")
    if not isinstance(data, dict):
        raise PersonaFormatError(SHAPE, "the top level must be a mapping (key: value)", 1, 1)
    return data


def _decode(source: str | bytes) -> str:
    if isinstance(source, bytes):
        if len(source) > MAX_BYTES:
            raise PersonaFormatError(SYNTAX, f"file is larger than {MAX_BYTES} bytes")
        try:
            text = source.decode("utf-8")
        except UnicodeDecodeError as exc:
            raise PersonaFormatError(
                SYNTAX, f"file is not valid UTF-8 (byte offset {exc.start})"
            ) from exc
    else:
        text = source
        if len(text.encode("utf-8", errors="surrogatepass")) > MAX_BYTES:
            raise PersonaFormatError(SYNTAX, f"file is larger than {MAX_BYTES} bytes")
    return text.removeprefix("\ufeff")


def _translate(exc: yaml.YAMLError) -> PersonaFormatError:
    if isinstance(exc, ReaderError):
        return PersonaFormatError(SYNTAX, f"invalid character at character offset {exc.position}")
    mark = getattr(exc, "problem_mark", None) or getattr(exc, "context_mark", None)
    if isinstance(exc, ComposerError) and "single document" in str(exc.context or ""):
        return _format_error(SYNTAX, "more than one YAML document", mark)
    if isinstance(exc, ConstructorError):
        return _format_error(SYNTAX, "unsupported value or tag", mark)
    if isinstance(exc, ScannerError):
        return _format_error(SYNTAX, "YAML syntax error", mark)
    if isinstance(exc, ParserError):
        return _format_error(SYNTAX, "YAML structure error (check indentation)", mark)
    return _format_error(SYNTAX, "invalid YAML", mark)


def _format_error(code: str, problem: str, mark: yaml.Mark | None) -> PersonaFormatError:
    if mark is None:
        return PersonaFormatError(code, problem)
    return PersonaFormatError(code, problem, mark.line + 1, mark.column + 1)
