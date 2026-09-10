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
                    reason=f"prefix: {prefix}, note: {note}"
                )
            ]
    
    return []

def main():
    print("Hash Identifier")
    user_input = input("Enter a string: ")
    candidates = identify(user_input)
    print(candidates)

if __name__ == "__main__":
    main()