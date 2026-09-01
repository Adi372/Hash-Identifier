from dataclasses import dataclass


@dataclass(frozen=True)
class Candidate:
    algorithm: str
    confidence: str
    reason: str


OTHER_FORMAT = {
    "$1$": "md5crypt",
    "$5$": "sha256crypt",
    "$6$": "sha512crypt",
    "$apr1$": "Apache MD5",
    "$P$": "phpass",
    "$H$": "phpass",
}

SPECIAL_FORMAT = {
    "$2a$": "bcrypt",
    "$2b$": "bcrypt",
    "$2y$": "bcrypt",
}

ARGON2 = {
    "$argon2d$": "Argon2d",
    "$argon2i$": "Argon2i",
    "$argon2id$": "Argon2id",
}

HEX_STRING = {
    32: "MD5",
    40: "SHA-1",
    56: "SHA-224",
    64: "SHA-256",
    96: "SHA-384",
    128: "SHA-512",
}


def is_special_format(text: str) -> list[Candidate]:
    for prefix, algo in SPECIAL_FORMAT.items():
        if len(text) == 60 and text.startswith(prefix):
            return [
                Candidate(
                    algorithm=algo,
                    confidence="high",
                    reason=f"Given hash starts with {prefix} and has length 60",
                )
            ]

    return []


def is_argon2(text: str) -> list[Candidate]:
    for prefix, algo in ARGON2.items():
        if text.startswith(prefix):
            return [
                Candidate(
                    algorithm=algo,
                    confidence="high",
                    reason=f"Given hash starts with {prefix}",
                )
            ]

    return []


def is_other_format(text: str) -> list[Candidate]:
    for prefix, algo in OTHER_FORMAT.items():
        if text.startswith(prefix):
            return [
                Candidate(
                    algorithm=algo,
                    confidence="high",
                    reason=f"Given hash starts with {prefix}",
                )
            ]

    return []


def is_hex_string(text: str) -> list[Candidate]:
    candidates = []

    for length, algo in HEX_STRING.items():
        if len(text) == length and all(
            c in "0123456789abcdefABCDEF" for c in text
        ):
            candidates.append(
                Candidate(
                    algorithm=algo,
                    confidence="medium",
                    reason=f"Hash has length {length} and contains only hexadecimal characters",
                )
            )

    return candidates


def phc_fallback(text: str) -> list[Candidate]:
    if text.startswith("$"):
        rest = text[1:]

        if "$" in rest:
            algo_name = rest.split("$", 1)[0]

            if algo_name and all(c.isalnum() or c in "-_" for c in algo_name):
                return [
                    Candidate(
                        algorithm=f"PHC string ({algo_name})",
                        confidence="low",
                        reason="unrecognized PHC-style string; algorithm name extracted from the first field",
                    )
                ]

    return []


def jwt_check(text: str) -> list[Candidate]:
    if text.startswith("eyJ"):
        return [
            Candidate(
                algorithm="JWT (not a hash)",
                confidence="high",
                reason="starts with `eyJ`, a common signature of a Base64URL-encoded JWT header",
            )
        ]

    return []


def base64_check(text: str) -> list[Candidate]:
    if any(c in text for c in "+/=") and len(text) > 8:
        return [
            Candidate(
                algorithm="Base64 blob (not a hash)",
                confidence="medium",
                reason="contains Base64-specific characters and is longer than 8 characters",
            )
        ]

    return []


def identify(raw_input: str) -> list[Candidate]:
    text = raw_input.strip()

    if not text:
        return []

    candidates = is_special_format(text)
    if candidates:
        return candidates

    candidates = is_argon2(text)
    if candidates:
        return candidates

    candidates = is_other_format(text)
    if candidates:
        return candidates

    candidates = is_hex_string(text)
    if candidates:
        return candidates

    candidates = phc_fallback(text)
    if candidates:
        return candidates

    candidates = jwt_check(text)
    if candidates:
        return candidates

    candidates = base64_check(text)
    if candidates:
        return candidates

    return []


# print(identify(""))
# print(identify("$2b$..."))
# print(identify("$argon2id$..."))
# print(identify("$6$salt$something"))
# print(identify("5f4dcc3b5aa765d61d8327deb882cf99"))
# print(identify("2fd4e1c67a2d28fced849ee1bb76e7391b93eb12"))
# print(identify("$unknown$v=19$parameters$salt$hash"))
# print(identify("eyJhbGciOiJIUzI1NiJ9.eyJzdWIiOiIxMjMifQ.signature"))
# print(identify("SGVsbG8gV29ybGQ="))
# print(identify("hello123"))

