"""
hash_identifier.py

Identify what kind of hash a string is,
by inspecting its shape.
"""

from dataclasses import dataclass
from typing import Literal
import argparse

@dataclass(frozen=True)
class HashCandidate:
    algorithm: str
    confidence: str
    reason: str

# Argon2 hash rule
PREFIX_RULES = [
    # Argon2
    ("$argon2id$", "Argon2id", "modern PHC string"),
    ("$argon2i$", "Argon2i", "PHC string, side-channel-resistant variant"),

    # bcrypt
    ("$2b$", "bcrypt", "bcrypt 2b variant"),
    ("$2a$", "bcrypt", "bcrypt 2a variant"),
    ("$2y$", "bcrypt", "bcrypt 2y variant"),
]

HEX_CHARSET = frozenset(
    "0123456789abcdefABCDEF"
)

_MYSQL5_HEX_BODY_LENGTH = 40
_MYSQL5_TOTAL_LENGTH = _MYSQL5_HEX_BODY_LENGTH + 1

HEX_LENGTH_RULES = {
    16: ["MySQL323", "CRC-64"],
    32: ["MD5", "NTLM", "MD4", "RIPEMD-128"],
    40: ["SHA-1", "RIPEMD-160"],
    64: ["SHA-256", "SHA3-256"],
    96: ["SHA-384"],
    128: ["SHA-512", "SHA3-512"],
}

_DESCRYPT_CHARSET = frozenset(
    "./0123456789"
    "ABCDEFGHIJKLMNOPQRSTUVWXYZ"
    "abcdefghijklmnopqrstuvwxyz"
)

_DESCRYPT_CHARSET_LENGTH = 13

def _is_hex(text: str) -> bool:
    return bool(text) and all(c in HEX_CHARSET for c in text)

def _is_mysql5(text: str) -> bool:
    if len(text) != _MYSQL5_TOTAL_LENGTH or not text.startswith("*"):
        return False
    body = text[1:]
    return all(c in "0123456789ABCDEF" for c in body)

def _is_descrypt(text: str) -> bool:
    return (
        len(text) == _DESCRYPT_CHARSET_LENGTH
        and all(c in _DESCRYPT_CHARSET for c in text)
    )

def identify(raw_input: str) -> list[HashCandidate]:
    text = raw_input.strip()

    if not text:
        return []

    for prefix, algorithm, note in PREFIX_RULES:
        if text.startswith(prefix):
            return [
                HashCandidate(
                    algorithm=algorithm,
                    confidence="high",
                    reason=f"prefix `{prefix}` - {note}",
                )
            ]

    if _is_mysql5(text):
        return [
            HashCandidate(
                algorithm="MySQL5",
                confidence="high",
                reason="starts with `*` and contains exactly 40 uppercase hex characters",
            )
        ]

    if _is_descrypt(text):
        return [
            HashCandidate(
                algorithm="DES crypt",
                confidence="medium",
                reason="13 characters from the traditional DES crypt alphabet",
            )
        ]

    if text.startswith("$"):
        rest = text[1:]

        if "$" in rest:
            algo_name = rest.split("$", 1)[0]

            if algo_name and all(c.isalnum() or c in "-_" for c in algo_name):
                return [
                    HashCandidate(
                        algorithm=f"PHC string ({algo_name})",
                        confidence="low",
                        reason="unrecognized PHC-style string; algorithm name extracted from the first field",
                    )
                ]

    if text.startswith("eyJ"):
        return [
            HashCandidate(
                algorithm="JWT (not a hash)",
                confidence="high",
                reason="starts with `eyJ`, a common signature of a Base64URL-encoded JWT header",
            )
        ]

    if any(c in text for c in "+/=") and len(text) > 8:
        return [
            HashCandidate(
                algorithm="Base64 blob (not a hash)",
                confidence="medium",
                reason="contains Base64-specific characters and is longer than 8 characters",
            )
        ]

    if _is_hex(text):
        algorithms = HEX_LENGTH_RULES.get(len(text), [])

        candidates = []

        for index, algorithm in enumerate(algorithms):
            confidence = "medium" if index == 0 else "low"

            candidates.append(
                HashCandidate(
                    algorithm=algorithm,
                    confidence=confidence,
                    reason=f"{len(text)} hexadecimal characters",
                )
            )

        return candidates

    return []

def main() -> int:
    parser = argparse.ArgumentParser(
        description="Identify what kind of hash a string is."
    )

    parser.add_argument("hash", help="The hash string to identify",)
    args = parser.parse_args()
    candidates = identify(args.hash)
    if not candidates:
        print("No matching hash format found.")
        return 0

    print("Possible matches:\n")

    for index, candidate in enumerate(candidates, start=1):
        print(f"{index}. {candidate.algorithm}")
        print(f"   Confidence: {candidate.confidence}")
        print(f"   Reason: {candidate.reason}\n")
    return 0

if __name__ == "__main__":
    main()