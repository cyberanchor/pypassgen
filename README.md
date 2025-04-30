# PyPassGen

![Version](https://img.shields.io/badge/version-1.3.0-green) | ![Python](https://img.shields.io/badge/python-3.8+-green) | ![Last Commit](https://img.shields.io/github/last-commit/cyberanchor/pypassgen) | ![Issues](https://img.shields.io/github/issues/cyberanchor/pypassgen)

**PyPassGen** generates deterministic passwords from BIP-39 mnemonic phrases or automatically creates mnemonic phrases and passwords. Ideal for secure password management with high entropy and determinism.

## Features
- **Mnemonic Generation**: Creates BIP-39 mnemonic phrases in multiple languages (English, French, Spanish, Italian, Japanese, Korean, Chinese Simplified).
- **Deterministic Passwords**: Generates consistent passwords using PBKDF2-HMAC-SHA512 with 1,000,000 iterations.
- **Customizable**: Supports password lengths up to 1024 characters and up to 100 phrases in auto mode.
- **File Output**: Saves mnemonic phrases and passwords in a mnemonic-password format.
- **Entropy Calculation**: Logs password entropy in bits to assess strength.
- **Parallel Processing**: Uses multithreading for faster generation of multiple phrases.
- **Security**: Validates inputs, clears sensitive data from memory, and provides detailed colorized logging.

## Cryptographic Architecture
- **Mnemonic to Seed**: Converts BIP-39 mnemonics to a 512-bit seed using PBKDF2-HMAC-SHA512.
- **Key Derivation**: Derives a key with PBKDF2-HMAC-SHA512, 1,000,000 iterations, and a fixed salt (`0`).
- **Password Generation**: Maps a SHA-512 hash to an 88-character set (alphanumeric + symbols).
- **Entropy**: Calculates entropy as `H = log2(N^C)` (N=88, C=length).
- **Memory Safety**: Overwrites sensitive data after use.

## Installation
1. Clone the repository:
   ```bash
   git clone https://github.com/cyberanchor/pypassgen
   cd pypassgen
   ```
2. Install dependencies:
   ```bash
   pip install mnemonic colorama
   ```
3. Run the tool:
   ```bash
   python pypassgen.py --help
   ```

## Usage
### Command-Line Arguments
- `--mnemonic <phrase>`: BIP-39 mnemonic phrase for password generation.
- `--auto`: Auto-generate mnemonic phrases and passwords.
- `--phrases <N>`: Number of phrases (default: 1, max: 100).
- `--words <N>`: Words per phrase (12, 15, 18, 21, 24; default: 12).
- `--password-length <N>`: Password length (default: 12, max: 1024).
- `--language <lang>`: Mnemonic language (default: english).
- `--output <file>`: Save mnemonic phrases and passwords to a file.

### Examples
1. Generate a password from a mnemonic:
   ```bash
   python pypassgen.py --mnemonic "expire join uncover ..." --password-length 16
   ```
   **Output**:
   ```
   Generated Password: BsZwx:(36vBaSD^y
   ```

2. Auto-generate 3 phrases with 24 words and 32-character passwords:
   ```bash
   python pypassgen.py --auto --phrases 3 --words 24 --password-length 32 --output phrases.txt
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
   python pypassgen.py --auto --language french --password-length 20
   ```

## Password Entropy
Entropy measures password strength in bits (`H = log2(N^C)`, N=88 characters). PyPassGen logs entropy in DEBUG mode.
- **Examples**:
  - 12 characters: ~77.4 bits
  - 16 characters: ~103.2 bits
  - 32 characters: ~206.7 bits
- **Guidelines**:
  - `< 64 bits`: Weak (avoid).
  - `64–80 bits`: Minimum for basic security.
  - `80–128 bits`: Good for most applications.
  - `> 128 bits`: Excellent for high-security needs.

## File Output Format
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

## Changelog
### Version 1.3.0
- Added password entropy calculation and logging.
- Updated `--output` to save mnemonic-password pairs.
- Implemented parallel processing for faster generation.
- Limited `--phrases` to 100 in auto mode.
- Enhanced documentation with entropy guidelines and examples.

### Version 1.2.0
- Renamed to PyPassGen.
- Added max password length check (1024).
- Improved logging and mnemonic validation.
- Fixed output file directory creation.

### Version 1.1.0
- Fixed non-deterministic passwords with a fixed salt.
- Increased PBKDF2 iterations to 1,000,000.
