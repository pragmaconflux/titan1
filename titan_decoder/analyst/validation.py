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


def _flatten(value: Any, out: list[str], budget: list[int]) -> None:
    if budget[0] <= 0:
        return
    if isinstance(value, dict):
        for key in sorted(value, key=str):
            out.append(str(key))
            _flatten(value[key], out, budget)
    elif isinstance(value, (list, tuple)):
        for entry in value:
            _flatten(entry, out, budget)
    elif value is not None:
        text = str(value)
        budget[0] -= len(text)
        out.append(text)


def _item_text(item: Any) -> str:
    """Return an evidence item's values as raw text, in the token's encoding.

    This used to be ``json.dumps(item.to_dict())``, which escapes every
    non-ASCII and control character -- ``\\u0336``, ``\\u0000`` -- while the
    claim's tokens are extracted from raw text. An indicator containing any
    such character could therefore never be found in its own evidence, so an
    internationalized host or a unicode path made a correctly cited claim fail
    validation. Comparing raw values to raw tokens removes the mismatch.
    """
    source = item.to_dict() if hasattr(item, "to_dict") else item
    parts: list[str] = []
    _flatten(source, parts, [1 << 20])
    return "\n".join(parts).lower()


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
