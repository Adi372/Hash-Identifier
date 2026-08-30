HASH_LENGTHS = {
    32: ["MD5", "NTLM"],
    40: ["SHA-1"],
    64: ["SHA-256"],
    128: ["SHA-512"],
}

def algo_for_length(text):
    return HASH_LENGTHS.get(len(text), [])

print(algo_for_length("12345678901234567890123456789012"))