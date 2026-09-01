def is_NetNTLMv2(text):
    hash=text.split(":")[4]
    return len(hash) == 32 and all(c in "0123456789abcdefABCDEF" for c in hash)

print(is_NetNTLMv2("user::domain:challenge:0123456789abcdef0123456789abcdef:blob"))