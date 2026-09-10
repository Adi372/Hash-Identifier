"""
hash_identifier.py

Identify what kind of hash a string is,
by inspecting its shape.
"""
def identify(raw_input: str):
    text = raw_input.strip()
    if text:
        return []
    return []

def main():
    print("Hash Identifier")
    user_input = input("Enter a string: ")
    candidates = identify(user_input)
    print(candidates)

if __name__ == "__main__":
    main()