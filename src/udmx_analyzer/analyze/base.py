"""Rule framework.

A rule is a small object that inspects a :class:`Bundle` and yields zero or
more :class:`Finding` objects. Rules are registered with :func:`register` (used
as a decorator) so the engine can discover them without an explicit list.

Rules must be:

* **deterministic** — same input, same output;
* **evidence-bound** — every Finding they emit references real data;
* **side-effect free** — they read the bundle, never mutate it.
"""

from __future__ import annotations

from typing import Callable, Iterable, List, Type

from ..models import Bundle, Finding

# Populated by the @register decorator.
_RULES: List[Type["Rule"]] = []


class Rule:
    """Base class for diagnostic rules."""

    #: Stable, unique identifier (e.g. ``"WIFI-DEAUTH-STORM"``).
    rule_id: str = ""
    #: Human category used for grouping in reports.
    category: str = "general"

    def run(self, bundle: Bundle) -> Iterable[Finding]:  # pragma: no cover
        raise NotImplementedError


def register(cls: Type[Rule]) -> Type[Rule]:
    """Class decorator that adds a rule to the global registry."""

    if not cls.rule_id:
        raise ValueError(f"{cls.__name__} must define a rule_id")
    if any(r.rule_id == cls.rule_id for r in _RULES):
        raise ValueError(f"duplicate rule_id: {cls.rule_id}")
    _RULES.append(cls)
    return cls


def all_rules() -> List[Rule]:
    """Instantiate every registered rule."""

    return [cls() for cls in _RULES]


def iter_message_matches(
    bundle: Bundle, predicate: Callable[[str], bool]
):
    """Yield log events whose raw text satisfies ``predicate``.

    Centralizes the common "scan every log line" pattern so rules stay terse.
    """

    for ev in bundle.log_events:
        if predicate(ev.raw):
            yield ev
