from dataclasses import dataclass

PREFIX_RULES = [
    ("$2b$", "bcrypt"),
    ("$2a$", "bcrypt"),
    ("$argon2id$", "Argon2id"),
    ("$argon2i$", "Argon2i"),
]

HEX_RULES = [
    (32, "MD5 / NTLM"),
    (40, "SHA-1"),
    (64, "SHA-256"),
    (128, "SHA-512")
]

@dataclass(frozen=True)
class Candidate:
    algorithm: str
    confidence: str
    result: str

def identify(text: str) -> list[Candidate]:

    for prefix, algo in PREFIX_RULES:
            if text.startswith(prefix):
                return [
                    Candidate(
                        algorithm=algo,
                        confidence="high",
                        result=f"Hash contains prefix {prefix}"
                    )
                ]
            
    if all(c in "0123456789abcdefABCDEF" for c in text):
         for length, algo in HEX_RULES:
                 if len(text) == length:
                     return [
                         Candidate(
                             algorithm=algo,
                             confidence="high",
                             result=f"Length of hash is {len(text)}"
                         )
                     ]
    
    return []

print(identify("5d41402abc4b2a76b9719d911017c592"))
print(identify("hello"))
