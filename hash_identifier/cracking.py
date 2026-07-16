"""
Optional integration hooks for downstream cracking tools.

This module *suggests* command lines for hashcat / John the Ripper based on an
identified hash. It never executes anything and never attempts to crack — it
only formats ready-to-copy commands so an operator can drop the hash straight
into their own tooling.
"""

from __future__ import annotations
from typing import Optional
from .engine import Candidate

def hashcat_command(
    candidate: Candidate,
    hashfile: str = "hashes.txt",
    wordlist: str = "rockyou.txt",
) -> Optional[str]:
    """Return a suggested hashcat command, or ``None`` if unsupported."""
    mode = candidate.hashcat_mode
    if not mode or mode in {"—", "-", ""}:
        return None
    return f"hashcat -a 0 -m {mode} {hashfile} {wordlist}"

def john_command(candidate: Candidate, hashfile: str = "hashes.txt") -> Optional[str]:
    """Return a suggested John the Ripper command, or ``None`` if unsupported."""
    fmt = candidate.john_format
    if not fmt:
        return None
    return f"john --format={fmt} {hashfile}"

def suggestions(candidate: Candidate, hashfile: str = "hashes.txt") -> dict:
    """Return both hashcat and John suggestions for *candidate*."""
    return {
        "hashcat": hashcat_command(candidate, hashfile=hashfile),
        "john": john_command(candidate, hashfile=hashfile),
    }
