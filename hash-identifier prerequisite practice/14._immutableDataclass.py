from dataclasses import dataclass
@dataclass(frozen=True)
class Candidate:
    algorithm: str
    confidence: str
    reason: str

candidate = Candidate(
    algorithm="MD5",
    confidence="medium",
    reason="32 hexadecimal characters"
)
print("Algorithm: ", candidate.algorithm)
print("Confidence: ", candidate.confidence)
print("Reason: ", candidate.reason)

candidate.algorithm = "SHA-256"