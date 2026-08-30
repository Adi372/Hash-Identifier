def split_record(text):
    return text.split(":")

print(split_record("user::domain:challenge:hash"))