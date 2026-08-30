# A dataclass is an easy way to create a class whose main job is to store data

from dataclasses import dataclass
@dataclass
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