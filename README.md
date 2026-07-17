# Hash Identifier

A production-grade Python tool for identifying cryptographic hash types and attempting to crack them using dictionary attacks.

## Features

- Identifies 30+ hash types (MD5, SHA-1, SHA-256, SHA-512, bcrypt, Argon2, and more)
- Dictionary-based hash cracking
- Clean CLI interface
- Importable Python module

## Installation

```bash
git clone https://github.com/grisheet/hash-identifier.git
cd hash-identifier
pip install -r requirements.txt
```

## Usage

### CLI

```bash
# Identify a hash
python -m hash_identifier identify <hash>

# Crack a hash
python -m hash_identifier crack <hash> --wordlist wordlist.txt
```

### Python API

```python
from hash_identifier import identify_hash, crack_hash

# Identify hash type
results = identify_hash("5d41402abc4b2a76b9719d911017c592")
print(results)

# Crack a hash
result = crack_hash("5d41402abc4b2a76b9719d911017c592", "wordlist.txt")
print(result)
```

## Supported Hash Types

MD5, SHA-1, SHA-224, SHA-256, SHA-384, SHA-512, SHA3-256, SHA3-512, bcrypt, Argon2, scrypt, NTLM, MySQL, Cisco, Drupal, WordPress, and many more.

## Project Structure

```
hash_identifier/
├── __init__.py      # Public API
├── __main__.py      # Entry point
├── cli.py           # CLI interface
├── engine.py        # Hash detection engine
├── cracking.py      # Hash cracking module
└── signatures.py    # Hash signatures/patterns
```

## License

MIT License
