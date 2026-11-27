"""Fill in the generated fakes before the lexicon is built (M1.6).

For every entity flagged `needs_generation` (FPE/SHIFT with an empty fake):
1. look the fake up in the vault (stable across runs and generator changes);
2. otherwise generate one (generate.py) and retry with the next attempt while it collides with
   any other form: equal canon, or one bounded inside the other (the bijection, ADR-0026);
3. add the usual alternative spellings (phone without spaces, dates in other formats);
4. return a FlatPersona whose entities all have fakes, plus whether the vault changed.

Fails closed: a value that can't get a unique fake after MAX_ATTEMPTS stops the engine.
"""

from dataclasses import replace

from veil.engine import generate
from veil.engine.vault import Vault
from veil.errors import ValidationFailed
from veil.persona.entities import Entity, FlatPersona
from veil.persona.policy import Policy
from veil.text.aho import PatternIndex
from veil.text.containment import contains_bounded
from veil.text.normalize import canon

MAX_ATTEMPTS = 64


def fill_generated(flat: FlatPersona, vault: Vault) -> FlatPersona:
    pending = [e for e in flat.entities if e.needs_generation]
    if not pending:
        return flat
    taken = _Taken(flat)
    surname = next(
        (e.fake_forms[0] for e in flat.entities if e.role == "family" and e.fake_forms), ""
    )
    shift = _shift_days(flat, vault)
    filled: dict[str, Entity] = {}
    for entity in pending:
        filled[entity.id] = _fill_entity(entity, vault, taken, surname, shift)
    entities = tuple(filled.get(e.id, e) if e.needs_generation else e for e in flat.entities)
    return replace(flat, entities=entities)


def _shift_days(flat: FlatPersona, vault: Vault) -> int:
    if flat.settings.date_shift_days:
        return flat.settings.date_shift_days
    if vault.shift_days is None:
        vault.shift_days = generate.random_shift(vault.seed)
        vault.dirty = True
    return vault.shift_days


def _fill_entity(entity: Entity, vault: Vault, taken: "_Taken", surname: str, shift: int) -> Entity:
    reals: list[str] = []
    fakes: list[str] = []
    for real in entity.real_forms:
        fake = vault.get(entity.role, real)
        if fake is None or not taken.free(real, fake):
            fake = _new_fake(entity, real, vault, taken, surname, shift)
            vault.put(entity.role, real, fake)
        taken.add(real, fake)
        reals.append(real)
        fakes.append(fake)
        for alt_real, alt_fake in generate.variants_for(entity.role, real, fake):
            if canon(alt_real) not in {canon(r) for r in reals} and taken.free(alt_real, alt_fake):
                taken.add(alt_real, alt_fake)
                reals.append(alt_real)
                fakes.append(alt_fake)
    return replace(entity, real_forms=tuple(reals), fake_forms=tuple(fakes), needs_generation=False)


def _new_fake(
    entity: Entity, real: str, vault: Vault, taken: "_Taken", surname: str, shift: int
) -> str:
    if entity.policy is Policy.SHIFT:
        for attempt in range(MAX_ATTEMPTS):
            moved = generate.shift_date(real, shift + attempt)
            if moved is None:
                break  # not a date we can parse: fall back to a shape-preserving fake
            if taken.free(real, moved):
                return moved
    for attempt in range(MAX_ATTEMPTS):
        candidate = generate.generate(
            entity.role, real, vault.seed, attempt, surname_initial=surname[:1]
        )
        if canon(candidate) != canon(real) and taken.free(real, candidate):
            return candidate
    raise ValidationFailed(
        f"could not generate a unique fake for {entity.id} after {MAX_ATTEMPTS} attempts"
    )


class _Taken:
    """Every form in use, for collision checks (equal canon or bounded containment)."""

    def __init__(self, flat: FlatPersona) -> None:
        self.reals: list[str] = []
        self.fakes: list[str] = []
        self.canon_all: set[str] = set()
        for e in flat.entities:
            for form in (*e.real_forms, *e.fake_forms):
                if canon(form):
                    self.canon_all.add(canon(form))
            self.reals.extend(e.real_forms)
            self.fakes.extend(e.fake_forms)
        self._index_reals = PatternIndex(self.reals)

    def free(self, real: str, fake: str) -> bool:
        f = canon(fake)
        if not f or (f in self.canon_all and f != canon(real)) or f == canon(real):
            return False
        if self._index_reals.find(fake):  # some real form sits inside this fake
            return False
        return not any(contains_bounded(fake, other) for other in self.reals)

    def add(self, real: str, fake: str) -> None:
        self.canon_all.update({canon(real), canon(fake)})
        self.reals.append(real)
        self.fakes.append(fake)
        self._index_reals = PatternIndex(self.reals)
