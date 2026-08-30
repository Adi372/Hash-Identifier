PREFIX_RULES = [
    ("$2b$", "bcrypt"),
    ("$2a$", "bcrypt"),
    ("$argon2id$", "Argon2id"),
]

def find_prefix(text):
    for prefix, algo in PREFIX_RULES:
        if text.startswith(prefix):
            return algo
    return None

print(find_prefix("$2b$12$abc"))      
print(find_prefix("$argon2id$..."))   
print(find_prefix("hello")) 