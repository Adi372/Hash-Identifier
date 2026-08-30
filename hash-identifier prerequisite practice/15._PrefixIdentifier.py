from dataclasses import dataclass

PREFIX_RULES = [
    ("$2b$", "bcrypt"),
    ("$2a$", "bcrypt"),
    ("$argon2id$", "Argon2id"),
    ("$argon2i$", "Argon2i"),
]

@dataclass(frozen=True)
class Candidate:
    algorithm: str
    confidence: str
    reason: str

def identify(text):
    for prefix, algo in PREFIX_RULES:
        if text.startswith(prefix):
            return [
                Candidate(
                    algorithm = algo,
                    confidence = "high",
                    reason = f"Matches {prefix} prefix"
                )
            ]

    return []

print(identify("$2b$12$abc"))
print(identify("$argon2id$..."))
print(identify("hello"))