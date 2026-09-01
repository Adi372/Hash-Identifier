def is_NetNTLMv1(text):
    part = text.split(":")[3]
    return len(part) == 48 and all(c in "0123456789abcdefABCDEF" for c in part)

print(is_NetNTLMv1("user::domain:0123456789abcdef0123456789abcdef0123456789abcdef"))