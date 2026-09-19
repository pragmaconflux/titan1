"""Answer validation: citations must resolve, and must actually support the claim.

Model output is untrusted, and the ledger it reads from quotes attacker-
controlled decoded content. Validation is the only thing standing between a
manipulated or hallucinated answer and an analyst reading it as fact, so an
answer is accepted only when three things hold:

1. every citation resolves to a real ledger entry;
2. every factual line carries at least one citation;
3. every concrete indicator a line asserts -- address, domain, URL, hash,
   rule id, ATT&CK technique -- actually appears in the evidence that line
   cites.

The third check is what makes a citation mean something. Checking only that a
citation *resolves* accepts "exfiltrates credentials to 10.0.0.5 [node:0]"
whenever node:0 exists, regardless of whether node:0 mentions that address.
The second matters because the first version required citations on bullet
lines only: a fabricated claim written as an ordinary sentence carried no
citation and passed unexamined.

Rejection is safe. The engine falls back to the deterministic answer and
records the reasons, so a false reject costs an explanation while a false
accept costs a fabricated forensic claim.
"""

from __future__ import annotations

from dataclasses import dataclass
import json
import re
from typing import Any, Iterable

from ..utils.helpers import extract_iocs
from .evidence import EvidenceIndex

_CITATION = re.compile(r"\[([a-z_]+:[^\]\s]+)\]")
_BULLET = re.compile(r"^(-|\*|\d+[.)])\s")
_NON_CLAIM_PREFIXES = ("Titan did not", "I cannot", "No evidence", "Inference:")

# Concrete identifiers a model must not invent. IOC shapes come from the
# engine's own extractor so the two agree on what counts as an indicator;
# rule and technique ids are added because they are equally falsifiable.
_RULE_ID = re.compile(r"\b(?:TITAN-\d+|YARA:[A-Za-z0-9_.:-]+)\b")
_ATTACK_ID = re.compile(r"\bT\d{4}(?:\.\d{3})?\b")


@dataclass(frozen=True)
class AnswerValidation:
    ok: bool
    citations: tuple[str, ...]
    invalid: tuple[str, ...]
    uncited_claim_lines: tuple[int, ...]
    unsupported_claim_lines: tuple[int, ...] = ()


def _hard_tokens(text: str) -> set[str]:
    """Return the concrete, falsifiable identifiers asserted in a line."""
    tokens: set[str] = set()
    # Citations name evidence ids, not claims about the world.
    stripped = _CITATION.sub(" ", text)
    for values in extract_iocs(stripped).values():
        tokens.update(str(value).lower() for value in values)
    tokens.update(match.group(0).lower() for match in _RULE_ID.finditer(stripped))
    tokens.update(match.group(0).lower() for match in _ATTACK_ID.finditer(stripped))
    return tokens


def _item_text(item: Any) -> str:
    try:
        return json.dumps(item.to_dict(), sort_keys=True, default=str).lower()
    except Exception:
        return str(item).lower()


def _corpus(items: Iterable[Any]) -> str:
    return "\n".join(_item_text(item) for item in items)


def validate_answer(text: str, index: EvidenceIndex) -> AnswerValidation:
    by_id = getattr(index, "by_id", {}) or {}
    citations = tuple(dict.fromkeys(_CITATION.findall(text)))
    invalid = tuple(c for c in citations if c not in by_id)

    ledger_corpus: str | None = None
    uncited: list[int] = []
    unsupported: list[int] = []

    for number, line in enumerate(text.splitlines(), 1):
        clean = line.strip()
        if not clean or clean.endswith(":"):
            continue

        cited = _CITATION.findall(clean)
        exempt = clean.startswith(_NON_CLAIM_PREFIXES)

        if not cited and not exempt:
            # Every factual line needs support, prose as much as bullets.
            uncited.append(number)
            continue

        tokens = _hard_tokens(clean)
        if not tokens:
            continue

        if cited:
            # Bind the claim to what it actually cites, not to the ledger at
            # large: citing an unrelated entry must not license an indicator.
            supporting = _corpus(by_id[c] for c in cited if c in by_id)
        else:
            # Labeled inference and refusals may go uncited, but they still
            # may not introduce indicators that appear nowhere in evidence.
            if ledger_corpus is None:
                ledger_corpus = _corpus(by_id.values())
            supporting = ledger_corpus

        if any(token not in supporting for token in tokens):
            unsupported.append(number)

    return AnswerValidation(
        ok=not invalid and not uncited and not unsupported,
        citations=citations,
        invalid=invalid,
        uncited_claim_lines=tuple(uncited),
        unsupported_claim_lines=tuple(unsupported),
    )
