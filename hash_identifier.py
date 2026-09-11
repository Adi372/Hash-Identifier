"""
hash_identifier.py

Identify what kind of hash a string is,
by inspecting its shape.
"""

from dataclasses import dataclass
from typing import Literal

@dataclass(frozen=True)
class HashCandidate:
    algorithm: str
    confidence: str
    reason: str

# Argon2 hash rule
PREFIX_RULES = [
    ("$argon2id$", "Argon2id", "modern PHC string"),
    ("$argon2i$", "Argon2i", "PHC string, side-channel-resistant variant"),
]

HEX_CHARSET = frozenset(
    "0123456789abcdefABCDEF"
)

HEX_LENGTH_RULES = {
    16: ["MySQL323", "CRC-64"],
    32: ["MD5", "NTLM", "MD4", "RIPEMD-128"],
    40: ["SHA-1", "RIPEMD-160"],
    64: ["SHA-256", "SHA3-256"],
    96: ["SHA-384"],
    128: ["SHA-512", "SHA3-512"],
}

def _is_hex(text: str) -> bool:
    return bool(text) and all(c in HEX_CHARSET for c in text)

def identify(raw_input: str):
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

def main():
    print("Hash Identifier")
    user_input = input("Enter a string: ")
    candidates = identify(user_input)
    print(candidates)

if __name__ == "__main__":
    main()