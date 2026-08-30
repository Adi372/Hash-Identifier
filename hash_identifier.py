"""
hash_identifier.py

Identify what kind of hash a string is,
by inspecting its shape.
"""

import argparse
import sys
from dataclasses import dataclass
from typing import Literal
from rich.console import Console
from rich.table import Table

Confidence = Literal["high", "medium", "low"]

@dataclass(frozen=True, slots=False)
class HashCandidate:
    algorithm: str
    confidence: Confidence
    reason: str

PREFIX_RULES: list[tuple[str, str, str]] = [
    # Argon2 family
    ("$argon2id$", "Argon2id", "modern PHC string"),
    ("$argon2i$", "Argon2i", "PHC string, side-channel-resistant variant"),

    # bcrypt
    ("$2b$", "bcrypt", "bcrypt 2b variant"),
    ("$2a$", "bcrypt", "bcrypt 2a variant"),
    ("$2y$", "bcrypt", "bcrypt 2y variant"),
]

HEX_CHARSET: frozenset[str] = frozenset(
    "0123456789abcdefABCDEF"
)

_HEX_UPPER_CHARSET: frozenset[str] = frozenset(
    "0123456789ABCDEF"
)

HEX_LENGTH_RULES: dict[int, list[str]] = {
    16: ["MySQL323", "CRC-64"],
    32: ["MD5", "NTLM", "MD4", "RIPEMD-128"],
    40: ["SHA-1", "RIPEMD-160"],
    64: ["SHA-256", "SHA3-256"],
    96: ["SHA-384"],
    128: ["SHA-512", "SHA3-512"],
}

def _is_hex(text: str) -> bool:
    """Return True if text is non-empty and contains only hex characters."""
    return bool(text) and all(c in HEX_CHARSET for c in text)

_MYSQL5_HEX_BODY_LENGTH = 40
_MYSQL5_TOTAL_LENGTH = _MYSQL5_HEX_BODY_LENGTH + 1

def _is_mysql5(text: str) -> bool:
    """Return True if text matches the MySQL5 password format"""
    if len(text) != _MYSQL5_TOTAL_LENGTH or not text.startswith("*"):
        return False
    body= text[1:]
    return all(c in _HEX_UPPER_CHARSET for c in body)

_DESCRYPT_CHARSET: frozenset[str] = frozenset(
    "./0123456789"
    "ABCDEFGHIJKLMNOPQRSTUVWXYZ"
    "abcdefghijklmnopqrstuvwxyz"
)
_DESCRYPT_CHARSET_LENGTH = 13

def _is_descrypt(text: str) -> bool:
    """Return True if text matche the traditional 13-character DES crypt format."""
    return(
        len(text) == _DESCRYPT_CHARSET_LENGTH
        and all(c in _DESCRYPT_CHARSET for c in text)
    )

def identify(raw_input: str) -> list[HashCandidate]:
    """Return ranked candidates for what algorithm produced raw_input"""
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

    if "::" in text and text.count(":") >=4:
        parts = text.split(":")
        
        if (len(parts) >= 6 and len(parts[4]) == 32 and _is_hex(parts[4])):
            return [
                HashCandidate(
                    algorithm="NetNTLMv2",
                    confidence="high",
                    reason="NTLM record with a 32-character hex response field",
                )
            ]
        
        if (len(parts) >=6 and len(parts[3]) == 48 and _is_hex(parts[3])):
            return [
                HashCandidate(
                    algorithm="NetNTLMv1",
                    confidence="high",
                    reason="NTLM record with a 48-character hex LM field",
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

        
    if _is_hex(text):
        algorithms = HEX_LENGTH_RULES.get(len(text), [])
        candidates: list[HashCandidate] = []
        for index, algorithm in enumerate(algorithms):
            confidence: Confidence = "medium" if index == 0 else "low"
            label = (
                "most likely candidate at this length"
                if index == 0
                else "also possible at this length"
            )
            candidates.append(
                HashCandidate(
                    algorithm=algorithm,
                    confidence=confidence,
                    reason=f"{len(text)} hexadecimal characters - {label}"
                )
            )

        return candidates


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

        # Step 5 — shape hints

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

    return []

def _build_argument_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        prog="hashid",
        description="Identify what kind of hash a string is.",
    )

    parser.add_argument(
        "hash",
        help="The hash string to identify",
    )

    parser.add_argument(
        "--top",
        "-n",
        type=int,
        default=5,
        help="Maximum number of candidates to display",
    )

    return parser

def _render_table(raw_input: str, candidates: list[HashCandidate], console: Console) -> None:
    table = Table(
        title=f"Candidates for: {raw_input.strip()}",
    )

    table.add_column(
        "algorithm",
        style="bold white",
        no_wrap=True,
    )

    table.add_column(
        "confidence",
        no_wrap=True,
    )

    table.add_column(
        "reason",
        style="dim",
    )

    confidence_colors: dict[Confidence, str] = {
        "high": "green",
        "medium": "yellow",
        "low": "cyan",
    }

    for candidate in candidates:
        color = confidence_colors[candidate.confidence]

        table.add_row(
            candidate.algorithm,
            f"[{color}]{candidate.confidence}[/{color}]",
            candidate.reason,
        )

    console.print(table)

def main() -> int:
    parser = _build_argument_parser()
    args = parser.parse_args()

    console = Console()

    candidates = identify(args.hash)

    if not candidates:
        console.print(
            "[red]No identification possible.[/red] "
            "The input did not match any known shape."
        )
        return 1

    trimmed = candidates[:args.top]

    _render_table(
        args.hash,
        trimmed,
        console,
    )

    if trimmed[0].confidence == "high":
        console.print(
            "\n[dim]Next step: try the matching cracker "
            "or verify the format manually.[/dim]"
        )

    return 0

if __name__ == "__main__":
    sys.exit(main())