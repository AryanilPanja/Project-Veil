"""Persona schema, version 1 (pydantic v2, strict).

Structure only: semantic checks (bijection, containment, cross-field rules) live in validate.py.

Why strict: yamlio deliberately keeps every scalar as text (except true/false/null). In its
default lax mode pydantic would undo that, turning "no" into False and "0123" into 123. In
strict mode a str field accepts only str and a bool field only a real true/false. The few
numeric fields are parsed from text explicitly, with range checks.

Errors never contain values: models hide inputs, repr/str are redacted, and parse_persona turns
pydantic errors into (code, field path, fixed problem) triples. For unknown fields, the unknown
key itself (user text) is never shown; a suggestion from the schema is shown instead.
"""

import difflib
import re
from collections.abc import Iterator
from dataclasses import dataclass
from typing import Annotated, Any, Literal, get_args

from pydantic import BaseModel, BeforeValidator, ConfigDict, Field, ValidationError

from veil.errors import ValidationFailed
from veil.persona.policy import Policy

SCHEMA = "E003"
VERSION = "E004"
SUPPORTED_VERSION = "1"


# ── Field types ───────────────────────────────────────────────────────────────


def _none_to_empty(value: Any) -> Any:
    return "" if value is None else value


def _none_to_false(value: Any) -> Any:
    return False if value is None else value


def _to_tuple(value: Any) -> Any:
    """Lists become tuples; "" / null become (); a single string becomes a 1-tuple."""
    if value is None or value == "":
        return ()
    if isinstance(value, str):
        return (value,)
    if isinstance(value, list):
        return tuple(value)
    return value


def _to_policy(value: Any) -> Any:
    if value is None or value == "":
        return None
    if isinstance(value, str):
        try:
            return Policy(value)
        except ValueError:
            raise ValueError("unknown policy") from None
    return value


def _int_parser(low: int, high: int, *, allow_empty: bool):
    pattern = re.compile(r"^[+-]?\d{1,6}$")

    def parse(value: Any) -> Any:
        if value is None or value == "":
            if allow_empty:
                return None
            raise ValueError("a number is required")
        if isinstance(value, bool) or not isinstance(value, str | int):
            raise ValueError("must be a whole number")
        text = str(value).strip()
        if not pattern.match(text):
            raise ValueError("must be a whole number")
        number = int(text)
        if not low <= number <= high:
            raise ValueError(f"must be between {low} and {high}")
        return number

    return parse


Text = Annotated[str, BeforeValidator(_none_to_empty)]
TextList = Annotated[tuple[Text, ...], BeforeValidator(_to_tuple)]
Flag = Annotated[bool, BeforeValidator(_none_to_false)]
OptPolicy = Annotated[Policy | None, BeforeValidator(_to_policy)]
PolicyValue = Annotated[Policy, BeforeValidator(_to_policy)]
YearNumber = Annotated[int | None, BeforeValidator(_int_parser(1, 10, allow_empty=True))]
TimeoutSeconds = Annotated[int, BeforeValidator(_int_parser(1, 600, allow_empty=False))]
ShiftDays = Annotated[int, BeforeValidator(_int_parser(-36500, 36500, allow_empty=False))]


class RedactedModel(BaseModel):
    model_config = ConfigDict(strict=True, extra="forbid", frozen=True, hide_input_in_errors=True)

    def __repr_args__(self) -> Iterator[tuple[str, Any]]:
        for name in type(self).model_fields:
            yield name, "<redacted>"

    def __str__(self) -> str:
        return f"{type(self).__name__}(<redacted>)"


def _many(model: type[BaseModel]) -> Any:
    return Annotated[tuple[model, ...], BeforeValidator(_to_tuple)]  # type: ignore[valid-type]


# ── Building blocks ───────────────────────────────────────────────────────────


class Pair(RedactedModel):
    real: Text = ""
    fake: Text = ""
    policy: OptPolicy = None
    allow_short: Flag = False
    contexts: TextList = ()
    enabled: Flag = True


class ListPair(RedactedModel):
    """Index-aligned lists: real[i] ↔ fake[i] (lengths are checked by the validator)."""

    real: TextList = ()
    fake: TextList = ()


class LabPair(Pair):
    aliases: ListPair = Field(default_factory=ListPair)


class PersonRef(Pair):
    relation: Text = ""


class CustomAttr(Pair):
    category: Text = ""


class PolicyOnly(RedactedModel):
    policy: OptPolicy = None


class ClassTerm(RedactedModel):
    enabled: Flag = False
    real: Text = ""
    fake: Text = ""
    phrases: ListPair = Field(default_factory=ListPair)


class YearOfStudy(RedactedModel):
    enabled: Flag = False
    real: YearNumber = None
    fake: YearNumber = None
    context_required: Flag = True


class Advisor(RedactedModel):
    real: Text = ""
    fake: Text = ""
    title: Pair = Field(default_factory=Pair)
    forms: ListPair = Field(default_factory=ListPair)


class Pet(RedactedModel):
    species: Pair = Field(default_factory=Pair)
    name: Pair = Field(default_factory=Pair)
    breed: Pair = Field(default_factory=Pair)
    policy: OptPolicy = None


class SensitiveEntry(RedactedModel):
    real: TextList = ()
    generalized: Text = ""
    policy: OptPolicy = None


# ── Sections ──────────────────────────────────────────────────────────────────


class Person(RedactedModel):
    first_name: Pair = Field(default_factory=Pair)
    short_name: Pair = Field(default_factory=Pair)
    last_name: Pair = Field(default_factory=Pair)
    full_name: Pair = Field(default_factory=Pair)
    middle_name: Pair = Field(default_factory=Pair)
    nicknames: _many(Pair) = ()
    name_in_other_scripts: _many(Pair) = ()
    gender: Pair = Field(default_factory=Pair)
    pronouns: Pair = Field(default_factory=Pair)
    date_of_birth: Pair = Field(default_factory=Pair)
    hometown: Pair = Field(default_factory=Pair)
    hometown_aliases: ListPair = Field(default_factory=ListPair)
    home_state: Pair = Field(default_factory=Pair)
    current_city: Pair = Field(default_factory=Pair)
    languages: Pair = Field(default_factory=Pair)


class Handles(RedactedModel):
    linux_user: Pair = Field(default_factory=Pair)
    github: Pair = Field(default_factory=Pair)
    gitlab: Pair = Field(default_factory=Pair)
    linkedin: Pair = Field(default_factory=Pair)
    twitter_x: Pair = Field(default_factory=Pair)
    discord: Pair = Field(default_factory=Pair)
    leetcode: Pair = Field(default_factory=Pair)
    kaggle: Pair = Field(default_factory=Pair)
    huggingface: Pair = Field(default_factory=Pair)
    google_scholar_id: Pair = Field(default_factory=Pair)
    orcid: Pair = Field(default_factory=Pair)
    personal_website: Pair = Field(default_factory=Pair)
    upi_ids: _many(Pair) = ()


class Education(RedactedModel):
    institution: Pair = Field(default_factory=Pair)
    aliases: ListPair = Field(default_factory=ListPair)
    domain: Pair = Field(default_factory=Pair)
    sub_domains: ListPair = Field(default_factory=ListPair)
    department: Pair = Field(default_factory=Pair)
    lab: LabPair = Field(default_factory=LabPair)
    degree: ClassTerm = Field(default_factory=ClassTerm)
    year_of_study: YearOfStudy = Field(default_factory=YearOfStudy)
    batch_year: Pair = Field(default_factory=Pair)
    advisor: Advisor = Field(default_factory=Advisor)
    research_area: Pair = Field(default_factory=Pair)
    roll_number: Pair = Field(default_factory=Pair)
    hostel_room: Pair = Field(default_factory=Pair)
    board: Pair = Field(default_factory=Pair)


class Work(RedactedModel):
    employer: Pair = Field(default_factory=Pair)
    team: Pair = Field(default_factory=Pair)
    manager: Pair = Field(default_factory=Pair)
    employee_id: Pair = Field(default_factory=Pair)
    role: Pair = Field(default_factory=Pair)


class Infra(RedactedModel):
    hostname: Pair = Field(default_factory=Pair)
    home_dir: Pair = Field(default_factory=Pair)
    clusters: _many(Pair) = ()
    cluster_usernames: _many(Pair) = ()
    slurm_accounts: _many(Pair) = ()
    wifi_ssids: _many(Pair) = ()
    ip_addresses: PolicyOnly = Field(default_factory=PolicyOnly)
    mac_addresses: PolicyOnly = Field(default_factory=PolicyOnly)
    private_repos: _many(Pair) = ()


class Ids(RedactedModel):
    aadhaar: Pair = Field(default_factory=Pair)
    pan: Pair = Field(default_factory=Pair)
    passport: Pair = Field(default_factory=Pair)
    voter_id: Pair = Field(default_factory=Pair)
    driving_licence: Pair = Field(default_factory=Pair)
    bank_accounts: _many(Pair) = ()
    cards: _many(Pair) = ()
    ifsc: Pair = Field(default_factory=Pair)
    address: _many(Pair) = ()
    pin_codes: _many(Pair) = ()


class Attributes(RedactedModel):
    pets: _many(Pet) = ()
    first_pet_name: Pair = Field(default_factory=Pair)
    first_school: Pair = Field(default_factory=Pair)
    childhood_street: Pair = Field(default_factory=Pair)
    favourite_food: Pair = Field(default_factory=Pair)
    favourite_sport_team: Pair = Field(default_factory=Pair)
    favourite_movie_book: Pair = Field(default_factory=Pair)
    hobbies: _many(Pair) = ()
    vehicle: Pair = Field(default_factory=Pair)
    custom: _many(CustomAttr) = ()


class Sensitive(RedactedModel):
    default_policy: PolicyValue = Policy.ASK
    ask_timeout_seconds: TimeoutSeconds = 120
    health: SensitiveEntry = Field(default_factory=SensitiveEntry)
    religion: SensitiveEntry = Field(default_factory=SensitiveEntry)
    caste: SensitiveEntry = Field(default_factory=SensitiveEntry)
    political: SensitiveEntry = Field(default_factory=SensitiveEntry)
    sexuality: SensitiveEntry = Field(default_factory=SensitiveEntry)


class Footprint(RedactedModel):
    paper_titles: _many(Pair) = ()
    thesis_title: Pair = Field(default_factory=Pair)
    public_repo_names: _many(Pair) = ()
    profile_urls_to_index: TextList = ()


class Numbers(RedactedModel):
    date_shift_days: ShiftDays = 0


class Persona(RedactedModel):
    version: Literal["1"]
    fidelity: Literal["semantic", "loose", "max"] = "semantic"
    veil_canary: Text = ""  # inserted by `veil persona import`; format checked there (T11)
    person: Person = Field(default_factory=Person)
    emails: _many(Pair) = ()
    phones: _many(Pair) = ()
    handles: Handles = Field(default_factory=Handles)
    education: _many(Education) = ()
    work: _many(Work) = ()
    people: _many(PersonRef) = ()
    infra: Infra = Field(default_factory=Infra)
    ids: Ids = Field(default_factory=Ids)
    attributes: Attributes = Field(default_factory=Attributes)
    sensitive: Sensitive = Field(default_factory=Sensitive)
    footprint: Footprint = Field(default_factory=Footprint)
    numbers: Numbers = Field(default_factory=Numbers)
    never_translate: TextList = ()
    never_reverse: TextList = ()


# ── Parsing with value-free errors ────────────────────────────────────────────


@dataclass(frozen=True)
class SchemaIssue:
    code: str
    path: str
    problem: str

    def __str__(self) -> str:
        return f"{self.code} {self.path}: {self.problem}"


class PersonaSchemaError(ValidationFailed):
    """The persona does not match the schema. Holds value-free issues (code, path, problem)."""

    def __init__(self, issues: tuple[SchemaIssue, ...]) -> None:
        first = issues[0]
        more = f" (+{len(issues) - 1} more)" if len(issues) > 1 else ""
        super().__init__(f"{first}{more}")
        self.issues = issues


def parse_persona(data: dict[str, Any]) -> Persona:
    """Validate a mapping from `load_yaml`. Raises PersonaSchemaError; never echoes values."""
    _check_version(data)
    error: ValidationError | None = None
    try:
        return Persona.model_validate(data)
    except ValidationError as exc:
        error = exc
    # Built outside the except block so no exception chain keeps the input alive.
    raise PersonaSchemaError(_issues(error))


def _check_version(data: dict[str, Any]) -> None:
    if "version" not in data:
        raise PersonaSchemaError((SchemaIssue(VERSION, "version", "is missing (expected 1)"),))
    if data["version"] != SUPPORTED_VERSION:
        raise PersonaSchemaError(
            (SchemaIssue(VERSION, "version", "unsupported (this veil reads version 1)"),)
        )


def _issues(error: ValidationError) -> tuple[SchemaIssue, ...]:
    issues: list[SchemaIssue] = []
    for item in error.errors(include_url=False, include_context=False, include_input=False):
        loc = tuple(item["loc"])
        kind = item["type"]
        if kind == "extra_forbidden":
            parent = loc[:-1]
            issues.append(
                SchemaIssue(SCHEMA, _path(parent) or "<top level>", _unknown_field(parent, loc))
            )
            continue
        issues.append(SchemaIssue(SCHEMA, _path(loc), _problem(kind, item.get("msg", ""))))
    return tuple(issues)


def _path(loc: tuple[Any, ...]) -> str:
    out = ""
    for part in loc:
        if isinstance(part, int):
            out += f"[{part}]"
        elif isinstance(part, str) and _is_schema_name(part):
            out += f".{part}" if out else part
        else:
            # A function-validator tag or other internal label: not useful, never user text
            continue
    return out


def _is_schema_name(part: str) -> bool:
    return bool(re.fullmatch(r"[a-z][a-z0-9_]*", part)) and "[" not in part


def _unknown_field(parent: tuple[Any, ...], loc: tuple[Any, ...]) -> str:
    model = _model_at(parent)
    if model is None:
        return "unknown field"
    key = loc[-1]
    names = list(model.model_fields)
    guess = difflib.get_close_matches(str(key), names, n=1, cutoff=0.6) if names else []
    # Only the schema's own field name is shown, never the key that was written.
    return f"unknown field (did you mean '{guess[0]}'?)" if guess else "unknown field"


def _model_at(loc: tuple[Any, ...]) -> type[BaseModel] | None:
    model: type[BaseModel] = Persona
    for part in loc:
        if isinstance(part, int):
            continue
        field = model.model_fields.get(part) if isinstance(part, str) else None
        if field is None:
            return None
        inner = _model_in(field.annotation)
        if inner is None:
            return None
        model = inner
    return model


def _model_in(annotation: Any) -> type[BaseModel] | None:
    """The model inside an annotation: Pair, tuple[Pair, ...], Annotated[...], X | None."""
    if isinstance(annotation, type) and issubclass(annotation, BaseModel):
        return annotation
    for arg in get_args(annotation):
        found = _model_in(arg)
        if found is not None:
            return found
    return None


_PROBLEMS: dict[str, str] = {
    "string_type": "must be text",
    "bool_type": "must be true or false",
    "tuple_type": "must be a list",
    "model_type": "must be a mapping (key: value)",
    "model_attributes_type": "must be a mapping (key: value)",
    "dict_type": "must be a mapping (key: value)",
    "missing": "is required",
    "literal_error": "has a value that is not allowed here",
    "enum": "has a value that is not allowed here",
    "frozen_instance": "cannot be changed",
}


def _problem(kind: str, msg: str) -> str:
    if kind in _PROBLEMS:
        return _PROBLEMS[kind]
    if kind == "value_error":
        # Our own validators raise fixed, value-free messages ("unknown policy", ranges).
        text = msg.removeprefix("Value error, ")
        return text if _is_fixed_message(text) else "invalid value"
    return "invalid value"


_FIXED_MESSAGES = re.compile(
    r"^(unknown policy|a number is required|must be a whole number"
    r"|must be between -?\d+ and -?\d+)$"
)


def _is_fixed_message(text: str) -> bool:
    return bool(_FIXED_MESSAGES.match(text))
