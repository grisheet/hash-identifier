"""
Hash type signature definitions.

Each :class:`HashSignature` is a self-contained description of a hash family:
a compiled regex that a candidate string *must* match to be considered, plus
metadata (hashcat/John mode, category, and a `prior` weight that encodes how
common the family is in real-world identification tasks).

Keeping every hash definition in one declarative list makes the detection
engine trivially extensible: add a new `HashSignature` here and the engine
picks it up automatically -- no engine code changes required.
"""

from __future__ import annotations

import re
from dataclasses import dataclass, field
from typing import Callable, Optional, Pattern


# ---------------------------------------------------------------------------
# Character-class predicates used by scoring adjusters below.
# ---------------------------------------------------------------------------
def _is_upper_hex(s: str) -> bool:
    return bool(s) and all(c in "0123456789ABCDEF" for c in s)


def _is_lower_hex(s: str) -> bool:
    return bool(s) and all(c in "0123456789abcdef" for c in s)


@dataclass(frozen=True)
class HashSignature:
    """A declarative description of one hash family.

    Attributes:
        name: Human-readable hash family name (e.g. "MD5").
        pattern: Compiled regex. A candidate must fully match to qualify.
        category: Coarse grouping: `raw` | `windows` | `unix` |
                  `checksum` | `kdf`.
        prior: Base likelihood weight (0..1). Higher == more commonly the
               *intended* answer when several families share a length.
        hashcat_mode: hashcat `-m` mode string, or `None` if unsupported.
        john_format: John the Ripper `--format` name, or `None`.
        description: Short note surfaced in the reasoning output.
        adjust: Optional callable `(candidate) -> float` returning a
                multiplicative factor applied to `prior` for this
                specific candidate. Used to disambiguate families that
                share a length/charset (e.g. LM prefers upper-case hex).
    """

    name: str
    pattern: Pattern[str]
    category: str
    prior: float
    hashcat_mode: Optional[str] = None
    john_format: Optional[str] = None
    description: str = ""
    self_identifying: bool = False
    adjust: Optional[Callable[[str], float]] = field(default=None, repr=False)

    def weight(self, candidate: str) -> float:
        """Return this signature's prior, scaled by any per-candidate adjuster."""
        factor = self.adjust(candidate) if self.adjust else 1.0
        return self.prior * factor


# ---------------------------------------------------------------------------
# Adjusters for length-ambiguous families.
# ---------------------------------------------------------------------------
def _lm_adjust(c: str) -> float:
    # LM hashes are canonically stored upper-case; lower-case strongly implies
    # a raw MD5/NTLM instead. Boost when upper, penalise when lower.
    if _is_upper_hex(c):
        return 2.6
    if _is_lower_hex(c):
        return 0.35
    return 1.0


def _ntlm_adjust(c: str) -> float:
    # NTLM is almost always emitted lower-case by dumping tools.
    return 1.15 if _is_lower_hex(c) else 0.9


def _md5_adjust(c: str) -> float:
    # MD5 output is conventionally lower-case; all-upper hex mildly disfavours
    # it (and correspondingly favours LM).
    return 0.7 if _is_upper_hex(c) else 1.0


# ---------------------------------------------------------------------------
# The signature registry. Order is irrelevant; the engine ranks by score.
# ---------------------------------------------------------------------------
SIGNATURES: list[HashSignature] = [
    # --- Prefixed / self-identifying formats (near-certain when matched) -----
    HashSignature(
        name="bcrypt",
        pattern=re.compile(r"^\$2[abxy]?\$\d{2}\$[./A-Za-z0-9]{53}$"),
        category="kdf",
        prior=0.99,
        hashcat_mode="3200",
        john_format="bcrypt",
        description="Blowfish-based adaptive KDF; '$2*$' prefix + cost factor.",
        self_identifying=True,
    ),
    HashSignature(
        name="Argon2",
        pattern=re.compile(
            r"^\$argon2(id|i|d)\$v=\d+\$m=\d+,t=\d+,p=\d+\$[A-Za-z0-9+/]+\$[A-Za-z0-9+/]+$"
        ),
        category="kdf",
        prior=0.99,
        hashcat_mode="—",  # hashcat lacks a single generic Argon2 mode
        john_format="argon2",
        description="Memory-hard KDF; PHC string '$argon2id$v=..$m=..' prefix.",
        self_identifying=True,
    ),
    HashSignature(
        name="sha512crypt",
        pattern=re.compile(r"^\$6\$[./A-Za-z0-9]{0,16}\$[./A-Za-z0-9]{86}$"),
        category="unix",
        prior=0.98,
        hashcat_mode="1800",
        john_format="sha512crypt",
        description="Linux /etc/shadow SHA-512 crypt; '$6$' prefix.",
        self_identifying=True,
    ),
    HashSignature(
        name="sha256crypt",
        pattern=re.compile(r"^\$5\$[./A-Za-z0-9]{0,16}\$[./A-Za-z0-9]{43}$"),
        category="unix",
        prior=0.98,
        hashcat_mode="7400",
        john_format="sha256crypt",
        description="Linux /etc/shadow SHA-256 crypt; '$5$' prefix.",
        self_identifying=True,
    ),
    HashSignature(
        name="md5crypt",
        pattern=re.compile(r"^\$1\$[./A-Za-z0-9]{0,8}\$[./A-Za-z0-9]{22}$"),
        category="unix",
        prior=0.97,
        hashcat_mode="500",
        john_format="md5crypt",
        description="Legacy Unix MD5 crypt; '$1$' prefix.",
        self_identifying=True,
    ),
    # --- Raw hex digests (length is the primary signal) ----------------------
    HashSignature(
        name="CRC32",
        pattern=re.compile(r"^[a-fA-F0-9]{8}$"),
        category="checksum",
        prior=0.60,
        hashcat_mode="11500",
        john_format="crc32",
        description="8 hex chars. A checksum, not a cryptographic hash.",
    ),
    HashSignature(
        name="MD5",
        pattern=re.compile(r"^[a-fA-F0-9]{32}$"),
        category="raw",
        prior=0.55,
        hashcat_mode="0",
        john_format="raw-md5",
        description="32 hex chars. Extremely common; shares length with NTLM/LM.",
        adjust=_md5_adjust,
    ),
    HashSignature(
        name="NTLM",
        pattern=re.compile(r"^[a-fA-F0-9]{32}$"),
        category="windows",
        prior=0.40,
        hashcat_mode="1000",
        john_format="nt",
        description="32 hex chars (MD4 of UTF-16LE password). Windows NT hash.",
        adjust=_ntlm_adjust,
    ),
    HashSignature(
        name="LM",
        pattern=re.compile(r"^[a-fA-F0-9]{32}$"),
        category="windows",
        prior=0.20,
        hashcat_mode="3000",
        john_format="lm",
        description="32 hex chars, canonically upper-case. Legacy LAN Manager.",
        adjust=_lm_adjust,
    ),
    HashSignature(
        name="SHA1",
        pattern=re.compile(r"^[a-fA-F0-9]{40}$"),
        category="raw",
        prior=0.75,
        hashcat_mode="100",
        john_format="raw-sha1",
        description="40 hex chars.",
    ),
    HashSignature(
        name="SHA256",
        pattern=re.compile(r"^[a-fA-F0-9]{64}$"),
        category="raw",
        prior=0.80,
        hashcat_mode="1400",
        john_format="raw-sha256",
        description="64 hex chars.",
    ),
    HashSignature(
        name="SHA512",
        pattern=re.compile(r"^[a-fA-F0-9]{128}$"),
        category="raw",
        prior=0.80,
        hashcat_mode="1700",
        john_format="raw-sha512",
        description="128 hex chars.",
    ),
]


def signatures_by_name() -> dict[str, HashSignature]:
    """Convenience index: family name -> signature."""
    return {s.name: s for s in SIGNATURES}
