# PyPassGen

![Version](https://img.shields.io/badge/version-1.3.3-green)  ![Python](https://img.shields.io/badge/python-3.8+-green)  ![Last Commit](https://img.shields.io/github/last-commit/cyberanchor/pypassgen)  ![Issues](https://img.shields.io/github/issues/cyberanchor/pypassgen)

**PyPassGen** generates deterministic passwords from BIP-39 mnemonic phrases or automatically creates mnemonic phrases and passwords.

## Features
- **Mnemonic generation**: creates BIP-39 mnemonic phrases in multiple languages (English, French, Spanish, Italian, Japanese, Korean, Chinese Simplified);
- **Deterministic passwords**: generates consistent passwords using PBKDF2-HMAC-SHA512 with 1000000 iterations;
- **Customizable**: supports password lengths up to 256 characters and up to 100 phrases in auto-gen mode;
- **File output**: saves mnemonic phrases and passwords in a mnemonic-password format;
- **Entropy calculation**: logs password entropy in bits to assess strength;
- **Parallel processing**: uses multithreading for faster generation of multiple phrases;
- **Security**: validates inputs, clears sensitive data from memory, provides detailed logging.

## Cryptographic architecture
- **Mnemonic to seed**: converts BIP-39 mnemonics to a 512-bit seed using PBKDF2-HMAC-SHA512;
- **Key derivation**: derives key with PBKDF2-HMAC-SHA512  1000000 iterations and a fixed salt (`0`);
- **Password generation**: maps SHA-512 hash to 88-character set (alphanumeric + symbols);
- **Entropy**: calculates entropy `H = log2(N^C)` (N=88, C=length);
- **Memory safety**: overwrites sensitive data after use.

## Installation
1. Clone the repository:
   ```bash
   git clone https://github.com/cyberanchor/pypassgen
   cd pypassgen
   ```
2. Install dependencies:
   ```bash
   pip install -r requirements.txt
   ```
3. Run:
   ```bash
   python pypassgen.py --help
   ```

## Usage
### Command-line arguments
- `--mnemonic <phrase>`: BIP-39 mnemonic phrase for password generation;
- `--auto-gen`: auto-generate mnemonic phrases and passwords;
- `--mnemonic-only`: generate only valid BIP-39 mnemonics (no passwords);
- `--phrases <N>`: number of phrases for `--auto-gen` (default: 1, max: 100);
- `--count <N>`: number of mnemonics for `--mnemonic-only` (default: 1, max: 10 000). If `N > 1000`, `--output` is required;
- `--words <N>`: words per phrase (12, 15, 18, 21, 24; default: 12);
- `--password-length <N>`: password length (default: 12, max: 256);
- `--language <lang>`: mnemonic language (default: english);
- `--output <file>`: save output to a file (one mnemonic per line for `--mnemonic-only`).

### Examples
1. Generate a password from a mnemonic:
   ```bash
   python pypassgen.py --mnemonic "expire join uncover ..." --password-length 16
   ```
   **Output**:
   ```
   Generated password: BsZwx:(36vBaSD^y
   ```

2. Auto-generate 3 phrases with 24 words and 32-character passwords:
   ```bash
   python pypassgen.py --auto-gen --phrases 3 --words 24 --password-length 32 --output phrases.txt
   ```
   **Output**:
   ```
   Mnemonic 1: polar ready danger stumble ... suffer venue
   Password 1: BsZwx:(36vBaSD^y4cg+H6e#]0p#(7iU
   Mnemonic 2: unaware they elder convince ... kind chalk
   Password 2: C0_M{fYrtiT;uZ2<0vmhcrr&}RKhjIl@
   Mnemonic 3: scissors impact salon fun ... often filter
   Password 3: $0IgG,phx@FzhgaY^oa%?5UYw(@SzwHV
   ```

3. Generate a French mnemonic with a 20-character password:
   ```bash
   python pypassgen.py --auto-gen --language french --password-length 20
   ```

## Password entropy
Entropy measures password strength in bits (`H = log2(N^C)`, N=88 characters). PyPassGen logs entropy in DEBUG mode.
- **Examples**:
  - 12 characters: ~77.4 bits
  - 16 characters: ~103.2 bits
  - 32 characters: ~206.7 bits
- **Guidelines**:
  - `< 64 bits`: Weak
  - `64–80 bits`: Minimum 
  - `80–128 bits`: Good 
  - `> 128 bits`: Excellent

## File output format
With `--output <file>`, saves in this format:
```
mnemonic1
password1
mnemonic2
password2
...
```
**Example `output.txt`**:
```
polar ready danger stumble ... suffer venue
BsZwx:(36vBaSD^y4cg+H6e#]0p#(7iU
unaware they elder convince ... kind chalk
C0_M{fYrtiT;uZ2<0vmhcrr&}RKhjIl@
```

Generate valid BIP-39 mnemonics only (one per line):

```bash
python pypassgen.py --mnemonic-only --count 10 --words 24 --language english
```

Write to a file:

```bash
python pypassgen.py --mnemonic-only --count 500 --output mnemonics.txt
```

Notes:
- `--count` defaults to 1.
- Maximum `--count` is 10,000.
- For `--count` > 1,000, `--output` is required.


### Mnemonic-only examples
Generate 1 mnemonic (12 words) to stdout:
```bash
python pypassgen.py --mnemonic-only
```

Generate 200 mnemonics (24 words) to stdout:
```bash
python pypassgen.py --mnemonic-only --count 200 --words 24
```

Generate 5000 mnemonics to a file (required for large counts):
```bash
python pypassgen.py --mnemonic-only --count 5000 --words 24 --output mnemonics.txt
```
