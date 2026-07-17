"""hash_identifier — heuristic hash-type identification.

Public API:
>>> from hash_identifier import HashIdentifier
>>> engine = HashIdentifier()
>>> ident = engine.identify("5f4dcc3b5aa765d61d8327deb882cf99")
>>> ident.best.name
'MD5'
"""

from .engine import (
    Candidate,
    HashIdentifier,
    Identification,
    describe_charset,
    shannon_entropy,
)
from .signatures import SIGNATURES, HashSignature

__all__ = [
    "HashIdentifier",
    "Identification",
    "Candidate",
    "HashSignature",
    "SIGNATURES",
    "shannon_entropy",
    "describe_charset",
]

__version__ = "1.0.0"
