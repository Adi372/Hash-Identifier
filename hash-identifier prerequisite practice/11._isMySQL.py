def isMySQL(text):
    return len(text[1:])==40 and text.startswith("*") and all(c in "0123456789ABCDEF" for c in text[1:])

print(isMySQL("*94BDCEBE19083CE2A1F959FD02F96410AF4CFCAB"))