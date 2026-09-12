# 🔐 Hash Identifier

A lightweight Python cybersecurity utility that identifies the **possible type of a hash or encoded string** by analyzing its structure, prefix, length, and character set.

> ⚠️ **Important:** Hash identification based on shape is not always definitive. Multiple algorithms can produce strings with the same length and character set, so the tool reports **possible matches and confidence levels** rather than claiming certainty.

---

## ✨ Features

* 🔎 Identify common hash formats
* 🧩 Detect hashes using known prefixes
* 📏 Analyze hash length and character set
* 🎯 Show multiple possible matches when formats overlap
* 📊 Provide confidence levels and reasons
* 🪪 Detect JWTs separately from hashes
* 📦 Detect Base64-like strings
* 🧱 Recognize generic PHC-style strings
* 💻 Simple command-line interface
* 🐍 Built entirely with Python

---

## 🛠️ Technologies Used

* **Python 3**
* `dataclasses`
* `argparse`
* Python type hints

No external Python packages are required.

---

## 📋 Supported Hashes & Formats

|  # | Hash / Format                  | Check Used                | Criteria                                                                                        | Confidence |
| -: | ------------------------------ | ------------------------- | ----------------------------------------------------------------------------------------------- | ---------- |
|  1 | **Argon2id**                   | Prefix check              | Starts with `$argon2id$`                                                                        | High       |
|  2 | **Argon2i**                    | Prefix check              | Starts with `$argon2i$`                                                                         | High       |
|  3 | **bcrypt 2b**                  | Prefix check              | Starts with `$2b$`                                                                              | High       |
|  4 | **bcrypt 2a**                  | Prefix check              | Starts with `$2a$`                                                                              | High       |
|  5 | **bcrypt 2y**                  | Prefix check              | Starts with `$2y$`                                                                              | High       |
|  6 | **MySQL5**                     | Prefix + length + charset | Starts with `*`, total length = **41**, remaining 40 characters are uppercase hexadecimal       | High       |
|  7 | **DES crypt**                  | Length + charset          | Exactly **13 characters**, all from `./0-9A-Za-z`                                               | Medium     |
|  8 | **MD5**                        | Hex + length              | Exactly **32 hexadecimal characters**                                                           | Medium     |
|  9 | **NTLM**                       | Hex + length              | Exactly **32 hexadecimal characters**                                                           | Low        |
| 10 | **MD4**                        | Hex + length              | Exactly **32 hexadecimal characters**                                                           | Low        |
| 11 | **RIPEMD-128**                 | Hex + length              | Exactly **32 hexadecimal characters**                                                           | Low        |
| 12 | **SHA-1**                      | Hex + length              | Exactly **40 hexadecimal characters**                                                           | Medium     |
| 13 | **RIPEMD-160**                 | Hex + length              | Exactly **40 hexadecimal characters**                                                           | Low        |
| 14 | **SHA-256**                    | Hex + length              | Exactly **64 hexadecimal characters**                                                           | Medium     |
| 15 | **SHA3-256**                   | Hex + length              | Exactly **64 hexadecimal characters**                                                           | Low        |
| 16 | **SHA-384**                    | Hex + length              | Exactly **96 hexadecimal characters**                                                           | Medium     |
| 17 | **SHA-512**                    | Hex + length              | Exactly **128 hexadecimal characters**                                                          | Medium     |
| 18 | **SHA3-512**                   | Hex + length              | Exactly **128 hexadecimal characters**                                                          | Low        |
| 19 | **Generic PHC string**         | `$` + field structure     | Starts with `$`, contains another `$`, and the first field contains valid identifier characters | Low        |
| 20 | **JWT** *(not a hash)*         | Prefix check              | Starts with `eyJ`                                                                               | High       |
| 21 | **Base64 blob** *(not a hash)* | Character check + length  | Contains `+`, `/`, or `=` and is longer than 8 characters                                       | Medium     |

### 📊 Current Coverage

* **18 hash algorithm candidates**
* **3 additional encoded/non-hash formats**
* **21 possible identification outputs**

---

## 🚀 Usage

Run the program from the terminal:

```bash
python hash_identifier.py "5d41402abc4b2a76b9719d911017c592"
```

Example output:

```text
Possible matches:

1. MD5
   Confidence: medium
   Reason: 32 hexadecimal characters

2. NTLM
   Confidence: low
   Reason: 32 hexadecimal characters

3. MD4
   Confidence: low
   Reason: 32 hexadecimal characters

4. RIPEMD-128
   Confidence: low
   Reason: 32 hexadecimal characters
```

---

## 🧪 Example Tests

### Argon2id

```bash
python hash_identifier.py '$argon2id$v=19$m=65536,t=3,p=4$abc$xyz'
```

Output:

```text
Argon2id
Confidence: high
```

### bcrypt

```bash
python hash_identifier.py '$2b$12$abcdefghijklmnopqrstuu'
```

Output:

```text
bcrypt
Confidence: high
```

### MySQL5

```bash
python hash_identifier.py '*0123456789ABCDEF0123456789ABCDEF01234567'
```

Output:

```text
MySQL5
Confidence: high
```

### MD5

```bash
python hash_identifier.py '5d41402abc4b2a76b9719d911017c592'
```

Possible result:

```text
MD5
Confidence: medium
```

### JWT

```bash
python hash_identifier.py 'eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9'
```

Output:

```text
JWT (not a hash)
Confidence: high
```

---

## 🧠 How It Works

The identifier follows a rule-based detection process:

```text
Input
  │
  ▼
Normalize input
  │
  ▼
Known prefix checks
  │
  ├── Argon2
  ├── bcrypt
  └── Other known formats
  │
  ▼
Specific format checks
  │
  ├── MySQL5
  └── DES crypt
  │
  ▼
PHC-style check
  │
  ▼
JWT check
  │
  ▼
Base64-like check
  │
  ▼
Hexadecimal check
  │
  ├── 16 characters
  ├── 32 characters
  ├── 40 characters
  ├── 64 characters
  ├── 96 characters
  └── 128 characters
  │
  ▼
Return possible candidates
```

The program does **not** try to crack or reverse the hash.

Instead, it asks:

> **"What formats could this string represent?"**

---

## 🎯 Confidence Levels

### 🟢 High

The format contains a strong identifying feature, such as a known prefix.

Example:

```text
$argon2id$...
```

The `$argon2id$` prefix strongly identifies Argon2id.

### 🟡 Medium

The format matches important structural characteristics, but there can still be ambiguity.

Example:

```text
32 hexadecimal characters
```

This is compatible with MD5, but also with several other algorithms.

### 🔴 Low

The string matches a broad characteristic shared by several algorithms.

Example:

```text
32 hexadecimal characters → NTLM
```

The shape alone cannot reliably distinguish NTLM from MD5, MD4, or RIPEMD-128.

---

## ⚠️ Limitations

Hash identification from a string's appearance is inherently limited.

For example:

```text
5d41402abc4b2a76b9719d911017c592
```

is 32 hexadecimal characters.

That alone does **not** prove that it is MD5.

It could potentially represent:

* MD5
* NTLM
* MD4
* RIPEMD-128

Therefore, this project uses **candidate matching and confidence levels** instead of pretending that the algorithm can always be known with certainty.

---

## 📁 Project Structure

```text
Hash-Identifier/
│
├── hash_identifier.py
└── README.md
```

---


## 🔐 Security Note

This tool is intended for **educational, defensive, and cybersecurity research purposes**.

It identifies possible formats based on observable characteristics. It does **not** crack passwords, recover plaintext, or guarantee the algorithm used to generate a hash.

---

## 👨‍💻 Author

**Aditya Pandey**

Built as a hands-on Python cybersecurity project to learn:

* Python
* CLI development
* Hash formats
* Pattern matching
* Input validation
* Cybersecurity tooling
* Rule-based detection
