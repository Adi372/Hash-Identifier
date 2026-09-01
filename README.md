# Hash Identifier

A simple Python command-line tool that identifies **possible hash algorithms** by analyzing the format, length, prefix, and character pattern of a given string.

> **Note:** Hash identification is based on the shape of the input. A hash's format can often match multiple algorithms, so the tool reports candidates with different confidence levels instead of claiming certainty when it cannot know.

---

## Features

* Identify common hash formats
* Detect algorithms using known prefixes
* Detect hexadecimal hashes using their length
* Detect special formats such as:

  * bcrypt
  * Argon2
  * MySQL5
  * DES crypt
  * NetNTLMv1
  * NetNTLMv2
* Recognize generic PHC strings
* Detect JWTs and Base64 blobs that are **not hashes**
* Show confidence level for each possible algorithm
* Command-line interface using `argparse`


---

## How It Works

The identifier follows a simple pipeline:

```text
                INPUT
                  │
                  ▼
              strip()
                  │
                  ▼
             Empty input?
             /          \
           Yes           No
            │             │
            ▼             ▼
           []       Prefix rules
                          │
                          ▼
                  Special formats
                          │
                          ▼
                   Hex + length
                          │
                          ▼
                    PHC fallback
                          │
                          ▼
                     Shape hints
                          │
                          ▼
                         []
```

The program does **not** crack or recover passwords.

It only examines the structure of the supplied string.

---

## Installation

Clone the repository:

```bash
git clone <your-repository-url>
cd hash-identifier
```

Install the dependencies using your preferred Python environment.

If you are using `uv`:

```bash
uv sync
```

---

## Usage

### Using Python

Run:

```bash
python hash_identifier.py HASH
```

Example:

```bash
python hash_identifier.py 5f4dcc3b5aa765d61d8327deb882cf99
```

The program will return the possible algorithms.

Example:

```text
Possible algorithm: MD5
```

---

### Using `uv`

You can also run:

```bash
uv run hash_identifier.py 5f4dcc3b5aa765d61d8327deb882cf99
```

---

## Example

### MD5

Input:

```text
5f4dcc3b5aa765d61d8327deb882cf99
```

Possible result:

```text
MD5
NTLM
MD4
RIPEMD-128
```

The reason multiple algorithms can appear is that several algorithms can produce a **32-character hexadecimal value**.

The tool therefore uses confidence levels.

---

## Confidence Levels

| Confidence | Meaning                                        |
| ---------- | ---------------------------------------------- |
| High       | The format strongly identifies the algorithm   |
| Medium     | The format is a good indication but not unique |
| Low        | The algorithm is another possible match        |

For example:

```text
Algorithm     Confidence
MD5           medium
NTLM          low
MD4           low
RIPEMD-128    low
```

This prevents the program from pretending that a hash can always be identified with certainty.

---

## Supported Detection Methods

### 1. Prefix Detection

Some formats contain recognizable prefixes.

For example:

```text
$2b$...
```

can identify:

```text
bcrypt
```

Similarly, Argon2 formats contain prefixes such as:

```text
$argon2id$
$argon2i$
```

---

### 2. Hexadecimal + Length

Some hashes consist entirely of hexadecimal characters.

The program checks:

```text
Character set
      +
Hash length
```

For example:

| Length | Possible algorithms        |
| -----: | -------------------------- |
|     32 | MD5, NTLM, MD4, RIPEMD-128 |
|     40 | SHA-1, RIPEMD-160          |
|     64 | SHA-256                    |
|    128 | SHA-512                    |

Length alone is **not enough** to guarantee the algorithm.

---

### 3. Special Formats

The program also checks formats such as:

```text
MySQL5
DES crypt
NetNTLMv1
NetNTLMv2
```

These formats have structural characteristics that can be checked directly.

---

### 4. PHC Strings

If a string starts with `$` but doesn't match one of the specifically known formats, the program attempts to extract the algorithm name from the PHC-style structure.

Example:

```text
$unknown$v=1$...
```

may produce:

```text
PHC string (unknown)
```

with low confidence.

---

### 5. JWT Detection

The program checks for strings beginning with:

```text
eyJ
```

These are commonly JWTs rather than hashes.

The tool reports:

```text
JWT (not a hash)
```

---

### 6. Base64 Detection

The program also looks for characteristics of Base64-encoded data.

Instead of incorrectly calling it a hash, it can report:

```text
Base64 blob (not a hash)
```

---

## Testing

Run the test suite with:

```bash
just test
```

Or with pytest directly:

```bash
pytest
```

The tests verify things such as:

* Prefix detection
* Hexadecimal detection
* Hash-length rules
* MySQL5 detection
* DES crypt detection
* NetNTLM detection
* PHC fallback
* JWT detection
* Base64 detection
* Confidence levels
* Immutable candidate objects

---

## Example CLI Commands

### Identify a hash

```bash
python hash_identifier.py 5f4dcc3b5aa765d61d8327deb882cf99
```

### Limit the number of results

```bash
python hash_identifier.py 5f4dcc3b5aa765d61d8327deb882cf99 --top 2
```

Short form:

```bash
python hash_identifier.py 5f4dcc3b5aa765d61d8327deb882cf99 -n 2
```

---

## Limitations

This tool **cannot always determine the exact hashing algorithm**.

For example:

```text
5f4dcc3b5aa765d61d8327deb882cf99
```

has 32 hexadecimal characters.

Multiple algorithms can produce a 32-character hexadecimal output.

Therefore, the tool reports:

```text
possible candidates
```

rather than pretending that the answer is always certain.

Other factors such as the application, database, salt format, protocol, or surrounding context may be required to determine the exact algorithm.

---

## Security Note

This project is intended for **educational and defensive cybersecurity purposes**.

Hash identification is only one step in understanding a hash. The tool does not:

* Crack passwords
* Perform brute-force attacks
* Recover plaintext passwords
* Exploit systems
* Bypass authentication

Only analyze hashes that you are authorized to examine.

---

## Learning Goals

This project is designed to practice Python fundamentals including:

* Functions
* Classes
* Dataclasses
* Type hints
* Lists
* Tuples
* Dictionaries
* Sets and `frozenset`
* String operations
* Slicing
* `all()` and `any()`
* `enumerate()`
* Generator expressions
* `argparse`
* Exception-free result handling
* Unit testing
* CLI application structure

---

Built as a cybersecurity/Python learning project.
