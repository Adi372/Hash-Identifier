DESCRYPT_CHARS = frozenset("./0123456789ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz")
def is_descrypt(text):
    return len(text) == 13 and all(c in DESCRYPT_CHARS for c in text)
print(is_descrypt("1234567890123"))