HEX_CHARS = frozenset("0123456789abcdefABCDEF")
def is_hex(text):
    return bool(text) and all(c in HEX_CHARS for c in text)
print(is_hex("5f4dcc3b5aa765d61d8327deb882cf99"))