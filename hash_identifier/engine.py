"""
Detection engine.

The engine is intentionally decoupled from I/O and CLI concerns. It takes a
string in and returns a structured :class:`Identification` describing the most
likely hash families and *why*.

Detection combines four independent signals:

1. **Regex signature matching** — a candidate must match a family's regex to
qualify at all. This gives us structural certainty for prefixed formats
(bcrypt, Argon2, $6$ crypt) and length gating for raw digests.
2. **Length heuristics** — encoded implicitly in the regexes (a 32-hex string
can only be MD5/NTLM/LM/CRC-family, never SHA-256).
3. **Character-set analysis** — used both for reasoning output and to break
ties (e.g. upper-case-only hex nudges toward LM; lower-case toward NTLM).
4. **Entropy scoring** — Shannon entropy per character, compared against the
theoretical maximum for the observed alphabet. Near-maximal entropy is
consistent with a real digest; conspicuously low entropy flags padding,
placeholders, or non-hash input, and lowers overall confidence.

Confidence for each candidate is its adjusted prior normalised across all
qualifying candidates, then modulated by the entropy sanity factor. This keeps
scores interpretable: they sum to ~1 across the plausible families for a given
input.
"""

from __future__ import annotations

import math
from collections import Counter
from dataclasses import dataclass, field
from typing import Optional

from .signatures import SIGNATURES, HashSignature


# ---------------------------------------------------------------------------
# Result containers.
# ---------------------------------------------------------------------------
@dataclass
class Candidate:
    """A single ranked hypothesis for an input hash."""

    name: str
    confidence: float      # 0..1, normalised across candidates
    hashcat_mode: Optional[str]
    john_format: Optional[str]
    category: str
    description: str

    def as_dict(self) -> dict:
        return {
            "name": self.name,
            "confidence": round(self.confidence, 4),
            "hashcat_mode": self.hashcat_mode,
            "john_format": self.john_format,
            "category": self.category,
            "description": self.description,
        }


@dataclass
class Identification:
    """Full result for one input string."""

    value: str
    length: int
    charset: str
    entropy_bits_per_char: float
    entropy_ratio: float      # observed / theoretical-max (0..1)
    candidates: list[Candidate] = field(default_factory=list)
    reasoning: list[str] = field(default_factory=list)

    @property
    def best(self) -> Optional[Candidate]:
        return self.candidates[0] if self.candidates else None

    def as_dict(self, top: int = 3) -> dict:
        return {
            "input": self.value,
            "length": self.length,
            "charset": self.charset,
            "entropy_bits_per_char": round(self.entropy_bits_per_char, 3),
            "entropy_ratio": round(self.entropy_ratio, 3),
            "candidates": [c.as_dict() for c in self.candidates[:top]],
            "reasoning": self.reasoning,
        }


# ---------------------------------------------------------------------------
# Low-level analysis helpers (pure functions; individually unit-testable).
# ---------------------------------------------------------------------------
def shannon_entropy(s: str) -> float:
    """Return Shannon entropy of *s* in bits per character.

    Defined as ``-Σ p(x) log2 p(x)`` over the observed symbol distribution.
    Returns 0.0 for empty/degenerate input.
    """
    if not s:
        return 0.0
    counts = Counter(s)
    n = len(s)
    entropy = -sum((c / n) * math.log2(c / n) for c in counts.values())
    return entropy + 0.0      # normalise -0.0 -> 0.0


def describe_charset(s: str) -> str:
    """Return a compact human-readable description of the alphabet used."""
    classes: list[str] = []
    if any(c.islower() and c in "abcdef" for c in s) or any(
        c.islower() and c.isalpha() for c in s
    ):
        pass      # handled below with finer buckets
    has_lower_hex = any(c in "abcdef" for c in s)
    has_upper_hex = any(c in "ABCDEF" for c in s)
    has_digit = any(c.isdigit() for c in s)
    has_lower_alpha = any(c.islower() and c.isalpha() and c not in "abcdef" for c in s)
    has_upper_alpha = any(c.isupper() and c.isalpha() and c not in "ABCDEF" for c in s)
    has_special = any(not c.isalnum() for c in s)

    if has_digit:
        classes.append("digits")
    if has_lower_hex:
        classes.append("a-f")
    if has_upper_hex:
        classes.append("A-F")
    if has_lower_alpha:
        classes.append("g-z")
    if has_upper_alpha:
        classes.append("G-Z")
    if has_special:
        specials = sorted({c for c in s if not c.isalnum()})
        classes.append("specials(" + "".join(specials) + ")")
    return ", ".join(classes) if classes else "empty"


def _alphabet_size(s: str) -> int:
    """Estimate the theoretical alphabet size for entropy normalisation."""
    has_hex = any(c in "abcdefABCDEF" for c in s)
    has_digit = any(c.isdigit() for c in s)
    has_alpha = any(c.isalpha() and c.lower() not in "abcdef" for c in s)
    has_special = any(not c.isalnum() for c in s)

    if has_special or has_alpha:
        # Looks like base64/PHC-ish content.
        return 64
    if has_hex and has_digit:
        return 16
    if has_digit and not has_hex:
        return 10
    return 16


# ---------------------------------------------------------------------------
# Engine.
# ---------------------------------------------------------------------------
class HashIdentifier:
    """Stateless, reusable detection engine.

    Instances are cheap and thread-safe (no mutable state); construct once and
    call :meth:`identify` for each input when batch processing.
    """

    def __init__(self, signatures: Optional[list[HashSignature]] = None) -> None:
        self.signatures = signatures if signatures is not None else SIGNATURES

    # -- public API --------------------------------------------------------
    def identify(self, raw: str, top: int = 3) -> Identification:
        """Analyse *raw* and return a ranked :class:`Identification`."""
        value = raw.strip()
        length = len(value)
        charset = describe_charset(value)
        entropy = shannon_entropy(value)
        alpha = _alphabet_size(value)
        max_entropy = math.log2(alpha) if alpha > 1 else 1.0
        entropy_ratio = entropy / max_entropy if max_entropy else 0.0

        result = Identification(
            value=value,
            length=length,
            charset=charset,
            entropy_bits_per_char=entropy,
            entropy_ratio=entropy_ratio,
        )

        if not value:
            result.reasoning.append("Empty input after trimming.")
            return result

        # 1. Collect qualifying signatures and their adjusted weights.
        matches: list[tuple[HashSignature, float]] = []
        for sig in self.signatures:
            if sig.pattern.match(value):
                matches.append((sig, sig.weight(value)))

        if not matches:
            result.reasoning.append(
                f"No known signature matched (length={length}, charset=[{charset}])."
            )
            return result

        # 2. Entropy sanity factor. Real digests fill their alphabet, so a very
        # low ratio (repetition/padding) discounts confidence uniformly.
        if entropy_ratio >= 0.85:
            entropy_factor = 1.0
        elif entropy_ratio >= 0.6:
            entropy_factor = 0.9
        else:
            entropy_factor = 0.7

        # 3. Normalise weights into confidences. Self-identifying formats
        # (bcrypt, Argon2, $N$ crypt) are exempt from the entropy discount:
        # their prefix is structural proof, not a statistical guess.
        total = sum(w for _, w in matches)
        for sig, w in matches:
            factor = 1.0 if sig.self_identifying else entropy_factor
            conf = (w / total) * factor
            result.candidates.append(
                Candidate(
                    name=sig.name,
                    confidence=conf,
                    hashcat_mode=sig.hashcat_mode,
                    john_format=sig.john_format,
                    category=sig.category,
                    description=sig.description,
                )
            )
        result.candidates.sort(key=lambda c: c.confidence, reverse=True)

        # 4. Build human-readable reasoning.
        result.reasoning.extend(self._explain(result, matches))
        return result

    def identify_many(self, items, top: int = 3):
        """Lazily identify an iterable of strings.

        Yields ``(original, Identification)`` pairs. Blank lines are skipped.
        Suitable for streaming thousands of hashes without buffering them all.
        """
        for raw in items:
            if raw is None:
                continue
            stripped = raw.strip()
            if not stripped:
                continue
            yield stripped, self.identify(stripped, top=top)

    # -- internals ---------------------------------------------------------
    @staticmethod
    def _explain(result: Identification, matches) -> list[str]:
        lines: list[str] = []
        lines.append(
            f"Length {result.length} narrows the field to "
            f"{len({s.name for s, _ in matches})} candidate family/families."
        )
        lines.append(f"Character set observed: [{result.charset}].")
        lines.append(
            f"Entropy {result.entropy_bits_per_char:.2f} bits/char "
            f"({result.entropy_ratio:.0%} of the max for this alphabet) — "
            + (
                "consistent with a real digest."
                if result.entropy_ratio >= 0.85
                else "lower than a random digest; treat with caution."
            )
        )
        # Explain the top disambiguation if several families share the length.
        names = {s.name for s, _ in matches}
        if {"MD5", "NTLM", "LM"} & names and len(names) > 1:
            if all(c in "0123456789ABCDEF" for c in result.value):
                lines.append(
                    "Upper-case-only hex favours LM (canonical casing) over "
                    "MD5/NTLM."
                )
            elif all(c in "0123456789abcdef" for c in result.value):
                lines.append(
                    "Lower-case hex favours MD5/NTLM over LM; MD5 and NTLM are "
                    "structurally identical and cannot be separated from the "
                    "digest alone."
                )
        return lines
