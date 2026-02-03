"""
PyPassGen: Deterministic Password Generator from BIP-39 Mnemonic Phrases

Overview:
PyPassGen is a robust, secure, and user-friendly command-line tool designed to generate
deterministic passwords from BIP-39 compliant mnemonic phrases or to automatically create
mnemonic phrases and their corresponding passwords.

Key Features:
- Generates BIP-39 mnemonic phrases in multiple languages (English, French, Spanish, etc.).
- Produces deterministic passwords using PBKDF2-HMAC-SHA512 with 1,000,000 iterations.
- Supports customizable password lengths (up to 256 characters) and multilingual mnemonic phrases.
- Saves generated mnemonic phrases and passwords to a file in mnemonic-password format.
- Provides detailed, colorized logging with entropy calculation for passwords.
- Implements parallel processing for efficient generation of multiple phrases.
- Ensures comprehensive input validation and memory cleanup for security.

Cryptographic Architecture:
- **Mnemonic to Seed**: Uses the `mnemonic` library to convert BIP-39 mnemonic phrases into
  a 512-bit seed via PBKDF2-HMAC-SHA512 with a fixed salt.
- **Key Derivation**: Applies PBKDF2-HMAC-SHA512 with 1,000,000 iterations and a fixed
  application-specific salt to derive a secure key from the seed.
- **Password Generation**: Generates a deterministic password by mapping a SHA-512 hash
  of the derived key to a character set (alphanumeric + symbols).
- **Entropy Calculation**: Computes password entropy in bits to assess strength.
- **Memory Safety**: Clears sensitive data (seed, key, hash) from memory after use to
  prevent potential memory-based attacks.

Software Architecture:
- **Object-Oriented Design**: Organized into classes (`Config`, `MnemonicGenerator`,
  `PasswordGenerator`, `CLIHandler`) for modularity and maintainability.
- **Config**: Manages application settings, including the fixed salt and logger configuration.
- **MnemonicGenerator**: Handles generation and validation of BIP-39 mnemonic phrases.
- **PasswordGenerator**: Performs secure password derivation with entropy calculation.
- **CLIHandler**: Manages command-line interface, argument parsing, parallel processing,
  and file output.
- **Error Handling**: Custom `PyPassGenError` exception class ensures robust error management.
- **Logging**: Detailed, colorized logging with DEBUG, INFO, WARNING, and ERROR levels.
"""

import argparse
import hashlib
import hmac
import logging
import math
import struct
import sys
import time
from typing import List, Tuple
from pathlib import Path
from colorama import init, Fore, Style
from mnemonic import Mnemonic
from concurrent.futures import ThreadPoolExecutor


USE_COLOR = sys.stdout.isatty()

if USE_COLOR:
    from colorama import Fore, Style
    RESET_ALL = Style.RESET_ALL
else:
    class _NoColor:
        def __getattr__(self, name):
            return ""
    Fore = _NoColor()
    RESET_ALL = ""




# Initialize colorama for cross-platform colored output
init(autoreset=True)

# Constants
APP_NAME = "PyPassGen"
APP_VERSION = "1.3.5"
DEFAULT_PASSWORD_LENGTH = 12
MAX_PASSWORD_LENGTH = 256
DEFAULT_NUM_PHRASES = 1
MAX_NUM_PHRASES = 100
MAX_MNEMONIC_ONLY_COUNT = 10_000
BIG_COUNT_REQUIRES_OUTPUT = 1_000  # Require --output when generating many mnemonics
PBKDF2_ITERATIONS = 1_000_000
BASE_CHARACTERS = "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789"
SYMBOLS = "!@#$%^&*()_+-=[]{};:,.<>?~"
SUPPORTED_LANGUAGES = ["english", "french", "spanish", "italian", "japanese", "korean", "chinese_simplified"]
STRENGTH_MAP = {12: 128, 15: 160, 18: 192, 21: 224, 24: 256}
FIXED_SALT = b'0'


# Password derivation helpers (v1.3.5+)
_HMAC_DOMAIN = b"PyPassGen\x00"

def _hmac_sha512_stream(key: bytes, context: bytes = b""):
    """
    Deterministic byte stream based on HMAC-SHA512(key, domain || context || counter).
    Yields 64-byte blocks.
    """
    counter = 0
    while True:
        ctr = struct.pack(">I", counter)
        yield hmac.new(key, _HMAC_DOMAIN + context + ctr, hashlib.sha512).digest()
        counter += 1


def _map_to_charset_uniform(charset: str, length: int, byte_blocks) -> str:
    """
    Map bytes to charset uniformly using rejection sampling (avoids modulo bias).
    byte_blocks: iterator yielding bytes objects.
    """
    m = len(charset)
    if m <= 0:
        raise ValueError("Empty charset")
    limit = (256 // m) * m  # largest multiple of m below 256

    out = []
    buf = b""
    idx = 0

    while len(out) < length:
        if idx >= len(buf):
            buf = next(byte_blocks)
            idx = 0
        b = buf[idx]
        idx += 1
        if b < limit:
            out.append(charset[b % m])

    return "".join(out)


# Color scheme for output
COLOR_SCHEME = {
    "info": Fore.GREEN,
    "error": Fore.RED,
    "warning": Fore.YELLOW,
    "success": Fore.CYAN,
    "highlight": Fore.MAGENTA
}

class PyPassGenError(Exception):
    """Base exception class for PyPassGen errors."""
    pass

class Config:
    """Configuration class for storing application settings."""
    
    def __init__(self):
        """
        Initialize configuration with fixed salt and logger.

        Attributes:
            salt: Fixed salt for deterministic PBKDF2 key derivation.
            logger: Configured logger instance.
        """
        self.salt = FIXED_SALT
        self.logger = self._setup_logger()

    @staticmethod
    def _setup_logger() -> logging.Logger:
        """
        Configure logging with colored output and detailed format.

        Returns:
            Configured logger instance.
        """
        logger = logging.getLogger(APP_NAME)
        # Default level is INFO; enable DEBUG with --verbose.
        logger.setLevel(logging.INFO)
        logger.propagate = False

        # Avoid duplicate handlers if Config() is created multiple times (e.g., in imports/tests).
        if not logger.handlers:
            # Log to stderr so stdout can be safely piped/redirected for generated output.
            console_handler = logging.StreamHandler(sys.stderr)
            console_handler.setLevel(logging.INFO)
            console_handler.setFormatter(logging.Formatter(
                f"{Fore.BLUE}%(asctime)s{RESET_ALL} - "
                f"{Fore.CYAN}%(levelname)-8s{RESET_ALL} - %(message)s"
            ))
            logger.addHandler(console_handler)

        return logger

class MnemonicGenerator:
    """Class for generating and validating BIP-39 mnemonic phrases."""
    
    def __init__(self, language: str = "english"):
        """
        Initialize MnemonicGenerator with specified language.

        Args:
            language: Language for mnemonic wordlist (default: english).

        Raises:
            PyPassGenError: If language is not supported.
        """
        if language not in SUPPORTED_LANGUAGES:
            raise PyPassGenError(f"Unsupported language: {language}. Supported: {SUPPORTED_LANGUAGES}")
        self.language = language
        self.mnemo = Mnemonic(language)
        self.logger = logging.getLogger(APP_NAME)
        self.logger.debug(f"{COLOR_SCHEME['info']}Initialized MnemonicGenerator with language: {language}")

    def generate(self, num_words: int = 12) -> str:
        """
        Generate a BIP-39 mnemonic phrase with specified number of words.

        Args:
            num_words: Number of words in the phrase (12, 15, 18, 21, or 24).

        Returns:
            Generated mnemonic phrase.

        Raises:
            PyPassGenError: If num_words is invalid or generation fails.
        """
        if num_words not in STRENGTH_MAP:
            self.logger.error(
                f"{COLOR_SCHEME['error']}Invalid number of words: {num_words}. "
                f"Supported: {list(STRENGTH_MAP.keys())}"
            )
            raise PyPassGenError(f"Invalid number of words: {num_words}")
        
        try:
            strength = STRENGTH_MAP[num_words]
            self.logger.info(
                f"{COLOR_SCHEME['info']}Generating {num_words}-word mnemonic phrase "
                f"in {self.language} with strength {strength} bits..."
            )
            mnemonic = self.mnemo.generate(strength=strength)
            self.logger.debug(f"{COLOR_SCHEME['success']}Mnemonic generated successfully")
            return mnemonic
        except Exception as e:
            self.logger.error(
                f"{COLOR_SCHEME['error']}Failed to generate mnemonic phrase: {str(e)}"
            )
            raise PyPassGenError(f"Mnemonic generation failed: {str(e)}")

    def validate(self, mnemonic: str) -> bool:
        """
        Validate a BIP-39 mnemonic phrase.

        Args:
            mnemonic: Mnemonic phrase to validate.

        Returns:
            True if valid, False otherwise.
        """
        try:
            self.logger.debug(f"{COLOR_SCHEME['info']}Validating mnemonic in {self.language}...")
            is_valid = self.mnemo.check(mnemonic)
            self.logger.debug(
                f"{COLOR_SCHEME['info']}Mnemonic validation result: {'Valid' if is_valid else 'Invalid'}"
            )
            return is_valid
        except Exception as e:
            self.logger.error(
                f"{COLOR_SCHEME['error']}Mnemonic validation failed: {str(e)}"
            )
            return False

class PasswordGenerator:
    """Class for generating deterministic passwords from mnemonic phrases."""
    
    def __init__(self, config: Config, language: str = "english"):
        """
        Initialize PasswordGenerator with configuration and language.

        Args:
            config: Configuration instance with salt and logger.
            language: Language for mnemonic validation (default: english).
        """
        self.config = config
        self.language = language
        self.mnemo = Mnemonic(language)
        self.logger = config.logger
        self.logger.debug(f"{COLOR_SCHEME['info']}Initialized PasswordGenerator with language: {language}")

    def generate(self, mnemonic: str, password_length: int = DEFAULT_PASSWORD_LENGTH) -> str:
        """
        Generate a deterministic password from a BIP-39 mnemonic phrase.

        Args:
            mnemonic: BIP-39 mnemonic phrase.
            password_length: Length of the generated password.

        Returns:
            Generated password.

        Raises:
            PyPassGenError: If mnemonic is invalid or password_length is invalid.
        """
        if not self.mnemo.check(mnemonic):
            self.logger.error(f"{COLOR_SCHEME['error']}Invalid mnemonic phrase provided for language: {self.language}")
            raise PyPassGenError("Invalid mnemonic phrase")

        if password_length <= 0:
            self.logger.error(f"{COLOR_SCHEME['error']}Password length must be positive: {password_length}")
            raise PyPassGenError("Password length must be positive")
        
        if password_length > MAX_PASSWORD_LENGTH:
            self.logger.error(
                f"{COLOR_SCHEME['error']}Password length exceeds maximum: {password_length} > {MAX_PASSWORD_LENGTH}"
            )
            raise PyPassGenError(f"Password length exceeds maximum: {MAX_PASSWORD_LENGTH}")

        characters = BASE_CHARACTERS + SYMBOLS
        self.logger.info(
            f"{COLOR_SCHEME['info']}Generating password of length {password_length} "
            f"using {len(characters)} characters..."
        )
        self.logger.debug(f"{COLOR_SCHEME['info']}Character set: {characters}")

        try:
            start_time = time.time()
            
            # Generate seed from mnemonic
            self.logger.debug(f"{COLOR_SCHEME['info']}Converting mnemonic to seed...")
            seed_bytes = Mnemonic.to_seed(mnemonic)
            seed = bytearray(seed_bytes)
            self.logger.debug(f"{COLOR_SCHEME['info']}Seed generated, size: {len(seed)} bytes")

            # Derive secure key with PBKDF2
            self.logger.debug(
                f"{COLOR_SCHEME['info']}Deriving key with PBKDF2-HMAC-SHA512, "
                f"{PBKDF2_ITERATIONS} iterations..."
            )
            key_bytes = hashlib.pbkdf2_hmac(
                'sha512', bytes(seed), self.config.salt, PBKDF2_ITERATIONS
            )
            key = bytearray(key_bytes)
            self.logger.debug(f"{COLOR_SCHEME['info']}Key derived, size: {len(key)} bytes")

            # Generate deterministic password from an HMAC-SHA512 byte stream (no repetition after 64 chars)
            self.logger.debug(f"{COLOR_SCHEME['info']}Generating password using HMAC-SHA512 stream + rejection sampling...")
            characters = BASE_CHARACTERS + SYMBOLS
            byte_blocks = _hmac_sha512_stream(bytes(key))
            password_str = _map_to_charset_uniform(characters, password_length, byte_blocks)

            # Calculate password entropy (uniform charset mapping)
            entropy = password_length * math.log2(len(characters))
            self.logger.debug(f"{COLOR_SCHEME['info']}Password entropy (upper bound): {entropy:.2f} bits")

            # Clear sensitive data from memory (best-effort; Python may keep copies internally)
            self.logger.debug(f"{COLOR_SCHEME['info']}Clearing sensitive data from memory (best-effort)...")
            for i in range(len(seed)):
                seed[i] = 0
            for i in range(len(key)):
                key[i] = 0
            end_time = time.time()
            
            self.logger.info(
                f"{COLOR_SCHEME['success']}Password generated in "
                f"{end_time - start_time:.6f} seconds"
            )
            self.logger.debug(f"{COLOR_SCHEME['highlight']}Generated password length: {len(password_str)}")
            
            return password_str
            
        except Exception as e:
            self.logger.error(
                f"{COLOR_SCHEME['error']}Password generation failed: {str(e)}"
            )
            raise PyPassGenError(f"Password generation failed: {str(e)}")

class CLIHandler:
    """Class for handling command-line interface and user interaction."""
    
    def __init__(self):
        """Initialize CLIHandler with configuration and generators."""
        self.config = Config()
        self.logger = self.config.logger
        self.mnemonic_generator = None
        self.password_generator = None

    def parse_arguments(self) -> argparse.Namespace:
        """
        Parse command-line arguments.

        Returns:
            Parsed arguments.
        """
        parser = argparse.ArgumentParser(
            usage=argparse.SUPPRESS,
            description=" ____        ____                 ____            \n|  _ \\ _   _|  _ \\ __ _ ___ ___  / ___| ___ _ __  \n| |_) | | | | |_) / _` / __/ __| | |  _ / _ \\ '_ \\ \n|  __/| |_| |  __/ (_| \\__ \\__ \\ | |_| |  __/ | | |\n|_|    \\__, |_|   \\__,_|___/___/  \\____|\\___|_| |_|  v1.3.5\n       |___/                                        \n\nGenerate deterministic passwords from BIP-39 mnemonic phrases, or generate new mnemonics.\n\nCryptography:\n- BIP-39 mnemonic generation/validation (wordlists depend on --language)\n- Password derivation: PBKDF2-HMAC-SHA512 (1,000,000 iterations) + deterministic fixed salt",
            formatter_class=argparse.RawDescriptionHelpFormatter,
            epilog='Examples (syntax + real commands)\n\n1) Show help\n   python pypassgen.py -h\n\n2) Generate a deterministic password from an existing mnemonic\n   python pypassgen.py --mnemonic "word1 word2 ... word12" --password-length 16\n   python pypassgen.py --mnemonic "..." --password-length 32 --language english\n\n3) Auto-generate mnemonics AND passwords (pairs)\n   # 3 phrases, 12 words each, English (default), save to file\n   python pypassgen.py --auto-gen --phrases 3 --words 12 --output phrases.txt\n   # 5 phrases, 24 words each, Italian\n   python pypassgen.py --auto-gen --phrases 5 --words 24 --language italian --output phrases_it.txt\n\n4) Generate ONLY mnemonics (no passwords)\n   # default: 1 mnemonic, 12 words, English, stdout (one mnemonic per line)\n   python pypassgen.py --mnemonic-only\n   # 200 mnemonics, 24 words, French, stdout\n   python pypassgen.py --mnemonic-only --count 200 --words 24 --language french\n   # Large batches: output file required when --count > 1000\n   python pypassgen.py --mnemonic-only --count 5000 --words 24 --output mnemonics_24w.txt\n\nNotes\n- Limits: --phrases max 100 (for --auto-gen); --count max 10000 (for --mnemonic-only)\n- Languages are restricted to SUPPORTED_LANGUAGES (see --help choices)'
        )

        # Keep a reference so we can print help from other parts of the program.
        self._parser = parser

        parser.add_argument(
            "--mnemonic", type=str,
            help=f"{COLOR_SCHEME['info']}BIP-39 mnemonic phrase to generate password from"
        )
        parser.add_argument(
            "--auto-gen", dest="auto_gen", action="store_true",
            help=f"{COLOR_SCHEME['info']}Auto-generate mnemonic phrases and passwords (pairs)"
        )
        # Backwards-compatible alias (hidden from --help).
        parser.add_argument(
            "--auto", dest="auto_gen", action="store_true", help=argparse.SUPPRESS
        )
        parser.add_argument(
            "--mnemonic-only", action="store_true",
            help=f"{COLOR_SCHEME['info']}Generate only BIP-39 mnemonics (no passwords)"
        )
        parser.add_argument(
            "--count", type=int, default=None,
            help=f"{COLOR_SCHEME['info']}Number of mnemonics to generate (default: 1, max: {MAX_MNEMONIC_ONLY_COUNT}). "
                 f"If set, overrides --phrases for --mnemonic-only"
        )
        parser.add_argument(
            "--phrases", type=int, default=DEFAULT_NUM_PHRASES,
            help=f"{COLOR_SCHEME['info']}Number of phrases to generate (default: {DEFAULT_NUM_PHRASES}, max: {MAX_NUM_PHRASES})"
        )
        parser.add_argument(
            "--words", type=int, default=12, choices=STRENGTH_MAP.keys(),
            help=f"{COLOR_SCHEME['info']}Number of words per phrase (default: 12)"
        )
        parser.add_argument(
            "--password-length", type=int, default=DEFAULT_PASSWORD_LENGTH,
            help=f"{COLOR_SCHEME['info']}Password length (default: {DEFAULT_PASSWORD_LENGTH}, max: {MAX_PASSWORD_LENGTH})"
        )
        parser.add_argument(
            "--language", type=str, default="english", choices=SUPPORTED_LANGUAGES,
            help=f"{COLOR_SCHEME['info']}Language for mnemonic phrases (default: english)"
        )
        parser.add_argument(
            "-v", "--verbose", action="store_true",
            help=f"{COLOR_SCHEME['info']}Enable verbose (DEBUG) logging to stderr"
        )
        parser.add_argument(
            "--output", type=str,
            help=f"{COLOR_SCHEME['info']}File to save generated mnemonic phrases and passwords"
        )
        
        # If started with no arguments, show help and exit cleanly.
        if len(sys.argv) == 1:
            parser.print_help()
            raise SystemExit(0)

        args = parser.parse_args()

        # If invoked with only -v/--verbose, behave like "show help".
        if getattr(args, "verbose", False) and len(sys.argv) == 2:
            parser.print_help()
            raise SystemExit(0)

        # Logging: keep stdout clean for generated output; logs go to stderr.
        # Default is INFO; enable DEBUG with --verbose.
        if getattr(args, "verbose", False):
            self.logger.setLevel(logging.DEBUG)
            for h in self.logger.handlers:
                h.setLevel(logging.DEBUG)
            self.logger.debug(f"{COLOR_SCHEME['info']}Parsed arguments: {vars(args)}")
        else:
            self.logger.setLevel(logging.INFO)
            for h in self.logger.handlers:
                h.setLevel(logging.INFO)

        return args

    def save_to_file(self, phrases: List[Tuple[str, str]], output_file: str) -> None:
        """
        Save generated mnemonic phrases and passwords to a file in mnemonic-password format.

        Args:
            phrases: List of (mnemonic, password) tuples.
            output_file: Path to output file.

        Raises:
            PyPassGenError: If file writing fails.
        """
        try:
            self.logger.info(f"{COLOR_SCHEME['info']}Saving {len(phrases)} phrase-password pairs to {output_file}...")
            output_path = Path(output_file)
            output_path.parent.mkdir(parents=True, exist_ok=True)
            with open(output_path, "w", encoding="utf-8") as f:
                for mnemonic, password in phrases:
                    f.write(f"{mnemonic}\n{password}\n")
            self.logger.info(
                f"{COLOR_SCHEME['success']}Saved {len(phrases)} phrase-password pairs to {output_file}"
            )
        except PermissionError as e:
            self.logger.error(
                f"{COLOR_SCHEME['error']}Permission denied when writing to {output_file}: {str(e)}"
            )
            raise PyPassGenError(f"Permission denied: {str(e)}")
        except OSError as e:
            self.logger.error(
                f"{COLOR_SCHEME['error']}Failed to write to {output_file}: {str(e)}"
            )
            raise PyPassGenError(f"File writing failed: {str(e)}")

    def generate_phrase(self, num_words: int, password_length: int) -> Tuple[str, str]:
        """
        Generate a single mnemonic phrase and its corresponding password.

        Args:
            num_words: Number of words in the mnemonic phrase.
            password_length: Length of the generated password.

        Returns:
            Tuple of (mnemonic, password).
        """
        mnemonic = self.mnemonic_generator.generate(num_words)
        password = self.password_generator.generate(mnemonic, password_length)
        return mnemonic, password

    def run(self) -> None:
        """Run the CLI application."""
        try:
            args = self.parse_arguments()
            
            self.logger.info(
                f"{COLOR_SCHEME['highlight']}{APP_NAME} v{APP_VERSION} starting..."
            )

            self.logger.warning(
                f"{COLOR_SCHEME['warning']}Compatibility notice: v1.3.5 changes the password derivation algorithm. "\
                f"Passwords generated by <=1.3.3 will NOT match for the same mnemonic."
            )
            
            self.mnemonic_generator = MnemonicGenerator(args.language)
            self.password_generator = PasswordGenerator(self.config, args.language)
            
            # Validate argument combinations
            if args.mnemonic and (args.auto_gen or args.mnemonic_only):
                self.logger.error(
                    f"{COLOR_SCHEME['error']}Cannot use --mnemonic together with --auto-gen/--mnemonic-only"
                )
                raise PyPassGenError("Cannot use --mnemonic together with --auto-gen/--mnemonic-only")
                self.logger.error(
                    f"{COLOR_SCHEME['error']}Cannot use --mnemonic together with --auto-gen/--mnemonic-only"
                )
                raise PyPassGenError("Invalid argument combination")

            if args.auto_gen and args.mnemonic_only:
                self.logger.error(
                    f"{COLOR_SCHEME['error']}Cannot use --auto-gen and --mnemonic-only together"
                )
                raise PyPassGenError("Invalid argument combination")

            # --- Mode 1: password from provided mnemonic ---
            if args.mnemonic:
                self.logger.info(f"{COLOR_SCHEME['info']}Processing provided mnemonic...")
                password = self.password_generator.generate(
                    args.mnemonic, args.password_length
                )
                print(
                    f"{COLOR_SCHEME['success']}Generated Password: "
                    f"{COLOR_SCHEME['highlight']}{password}{RESET_ALL}"
                )
                return

            # --- Mode 2: mnemonics only ---
            if args.mnemonic_only:
                # count defaults to 1; --count overrides (and for backwards-compatibility we also accept --phrases)
                count = args.count if args.count is not None else args.phrases
                if count <= 0:
                    raise PyPassGenError("--count must be positive")
                if count > MAX_MNEMONIC_ONLY_COUNT:
                    raise PyPassGenError(f"--count is too large (max: {MAX_MNEMONIC_ONLY_COUNT})")
                if count > BIG_COUNT_REQUIRES_OUTPUT and not args.output:
                    raise PyPassGenError(
                        f"For large volumes (>{BIG_COUNT_REQUIRES_OUTPUT}), --output is required"
                    )

                # Output: one mnemonic per line, no extra labels.
                if args.output:
                    self.logger.info(f"{COLOR_SCHEME['info']}Generating {count} mnemonics -> {args.output}")
                    try:
                        with open(args.output, "w", encoding="utf-8", buffering=1024 * 1024) as f:
                            for _ in range(count):
                                m = self.mnemonic_generator.generate(args.words)
                                if not self.mnemonic_generator.validate(m):
                                    raise PyPassGenError("Generated mnemonic failed validation")
                                f.write(m + "\n")
                    except OSError as e:
                        raise PyPassGenError(f"Cannot write to --output '{args.output}': {e}")
                    return
                else:
                    self.logger.info(f"{COLOR_SCHEME['info']}Generating {count} mnemonics to stdout")
                    for _ in range(count):
                        m = self.mnemonic_generator.generate(args.words)
                        if not self.mnemonic_generator.validate(m):
                            raise PyPassGenError("Generated mnemonic failed validation")
                        print(m)
                    return

            # --- Mode 3: auto-generate mnemonic + password pairs ---
            if not args.auto_gen:
                # UX: show help if the user did not select a mode.
                try:
                    self._parser.print_help()
                except Exception:
                    pass

                # Special case: running only with -v/--verbose should behave like "show help".
                if getattr(args, "verbose", False) and len(sys.argv) == 2:
                    return

                self.logger.error(
                    f"{COLOR_SCHEME['error']}No mode selected. Use --mnemonic, --mnemonic-only, or --auto-gen."
                )
                raise PyPassGenError("No mode selected")

            if args.phrases <= 0:
                self.logger.error(
                    f"{COLOR_SCHEME['error']}Number of phrases must be positive: {args.phrases}"
                )
                raise PyPassGenError("Number of phrases must be positive")

            if args.phrases > MAX_NUM_PHRASES:
                self.logger.error(
                    f"{COLOR_SCHEME['error']}Number of phrases exceeds maximum: {args.phrases} > {MAX_NUM_PHRASES}"
                )
                raise PyPassGenError(f"Number of phrases exceeds maximum: {MAX_NUM_PHRASES}")

            self.logger.info(f"{COLOR_SCHEME['info']}Generating {args.phrases} mnemonic phrases in parallel...")
            file_handle = None
            if args.output:
                # overwrite existing file for a clean run
                file_handle = open(args.output, "w", encoding="utf-8", buffering=1024 * 1024)

            try:
                with ThreadPoolExecutor() as executor:
                    futures = [
                        executor.submit(self.generate_phrase, args.words, args.password_length)
                        for _ in range(args.phrases)
                    ]
                    for i, future in enumerate(futures, 1):
                        mnemonic, password = future.result()
                        print(
                            f"{COLOR_SCHEME['success']}Mnemonic {i}: "
                            f"{COLOR_SCHEME['highlight']}{mnemonic}\n"
                            f"{COLOR_SCHEME['success']}Password {i}: "
                            f"{COLOR_SCHEME['highlight']}{password}{RESET_ALL}\n"
                        )
                        if file_handle:
                            file_handle.write(mnemonic + "\n" + password + "\n")
            finally:
                if file_handle:
                    file_handle.close()
        except PyPassGenError as e:
            self.logger.error(f"{COLOR_SCHEME['error']}{str(e)}")
            sys.exit(1)
        except KeyboardInterrupt:
            self.logger.warning(
                f"{COLOR_SCHEME['warning']}Operation interrupted by user"
            )
            sys.exit(1)
        except Exception as e:
            self.logger.error(
                f"{COLOR_SCHEME['error']}Unexpected error: {str(e)}"
            )
            sys.exit(1)

def main():
    """Main entry point for the application."""
    CLIHandler().run()

if __name__ == "__main__":
    main()

# Enable colors only when stdout is a TTY (prevents ANSI codes in redirected output)
USE_COLOR = sys.stdout.isatty()
RESET_ALL = RESET_ALL if USE_COLOR else ""
if not USE_COLOR:
    COLOR_SCHEME = {k: "" for k in COLOR_SCHEME}

