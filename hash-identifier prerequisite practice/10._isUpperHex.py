def is_upper_text(text):
    return bool(text) and all(c in "0123456789ABCDEF" for c in text)

print(is_upper_text("54AB"))