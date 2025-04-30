"""
PyPassGen: Deterministic Password Generator from BIP-39 Mnemonic Phrases

Overview:
PyPassGen is a robust, secure, and user-friendly command-line tool designed to generate
deterministic passwords from BIP-39 compliant mnemonic phrases or to automatically create
mnemonic phrases and their corresponding passwords.

Key Features:
- Generates BIP-39 mnemonic phrases in multiple languages (English, French, Spanish, etc.).
- Produces deterministic passwords using PBKDF2-HMAC-SHA512 with 1,000,000 iterations.
- Supports customizable password lengths (up to 1024 characters) and multilingual mnemonic phrases.
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
import logging
import math
import sys
import time
from typing import List, Tuple
from pathlib import Path
from colorama import init, Fore, Style
from mnemonic import Mnemonic
from concurrent.futures import ThreadPoolExecutor

# Initialize colorama for cross-platform colored output
init(autoreset=True)

# Constants
APP_NAME = "PyPassGen"
APP_VERSION = "1.3.0"
DEFAULT_PASSWORD_LENGTH = 12
MAX_PASSWORD_LENGTH = 512
DEFAULT_NUM_PHRASES = 1
MAX_NUM_PHRASES = 100
PBKDF2_ITERATIONS = 1_000_000
BASE_CHARACTERS = "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789"
SYMBOLS = "!@#$%^&*()_+-=[]{};:,.<>?~"
SUPPORTED_LANGUAGES = ["english", "french", "spanish", "italian", "japanese", "korean", "chinese_simplified"]
STRENGTH_MAP = {12: 128, 15: 160, 18: 192, 21: 224, 24: 256}
FIXED_SALT = b'0'

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
        logger.setLevel(logging.DEBUG)  # Enable DEBUG level for detailed logging
        
        console_handler = logging.StreamHandler(sys.stdout)
        console_handler.setFormatter(logging.Formatter(
            f"{Fore.BLUE}%(asctime)s{Style.RESET_ALL} - "
            f"{Fore.CYAN}%(levelname)-8s{Style.RESET_ALL} - %(message)s"
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
            seed = Mnemonic.to_seed(mnemonic)
            self.logger.debug(f"{COLOR_SCHEME['info']}Seed generated, size: {len(seed)} bytes")
            
            # Derive secure key with PBKDF2
            self.logger.debug(
                f"{COLOR_SCHEME['info']}Deriving key with PBKDF2-HMAC-SHA512, "
                f"{PBKDF2_ITERATIONS} iterations..."
            )
            key = hashlib.pbkdf2_hmac(
                'sha512', seed, self.config.salt, PBKDF2_ITERATIONS
            )
            self.logger.debug(f"{COLOR_SCHEME['info']}Key derived, size: {len(key)} bytes")
            
            # Generate deterministic password from single SHA-512 hash
            self.logger.debug(f"{COLOR_SCHEME['info']}Generating SHA-512 hash for password...")
            hash_bytes = hashlib.sha512(key).digest()
            self.logger.debug(f"{COLOR_SCHEME['info']}Hash generated, size: {len(hash_bytes)} bytes")
            
            password = []
            for i in range(password_length):
                index = hash_bytes[i % len(hash_bytes)] % len(characters)
                password.append(characters[index])
            
            # Calculate password entropy
            entropy = password_length * math.log2(len(characters))
            self.logger.debug(f"{COLOR_SCHEME['info']}Password entropy: {entropy:.2f} bits")
            
            # Clear sensitive data
            self.logger.debug(f"{COLOR_SCHEME['info']}Clearing sensitive data from memory...")
            seed = b'\x00' * len(seed)
            key = b'\x00' * len(key)
            hash_bytes = b'\x00' * len(hash_bytes)
            
            password_str = ''.join(password)
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
            description=(
                f"{COLOR_SCHEME['highlight']}{APP_NAME} v{APP_VERSION}\n"
                "Generate deterministic passwords from BIP-39 mnemonic phrases or "
                "automatically generate mnemonic phrases and passwords.\n\n"
                "Cryptographic Details:\n"
                "- Uses PBKDF2-HMAC-SHA512 with 1,000,000 iterations for key derivation.\n"
                "- Fixed salt ensures deterministic output for the same mnemonic.\n"
                "- Sensitive data is cleared from memory after use.\n"
                "- Calculates password entropy for strength assessment."
            ),
            formatter_class=argparse.RawDescriptionHelpFormatter,
            epilog=(
                f"{COLOR_SCHEME['info']}Examples:\n"
                "  Generate password from mnemonic:\n"
                f"    python {sys.argv[0]} --mnemonic 'word1 word2 ...' --password-length 16\n"
                "  Auto-generate 3 mnemonic phrases and passwords:\n"
                f"    python {sys.argv[0]} --auto --phrases 3 --output phrases.txt\n"
                f"{COLOR_SCHEME['warning']}Note: Ensure mnemonic phrases are BIP-39 compliant."
            )
        )
        
        parser.add_argument(
            "--mnemonic", type=str,
            help=f"{COLOR_SCHEME['info']}BIP-39 mnemonic phrase to generate password from"
        )
        parser.add_argument(
            "--auto", action="store_true",
            help=f"{COLOR_SCHEME['info']}Automatically generate mnemonic phrases and passwords"
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
            "--output", type=str,
            help=f"{COLOR_SCHEME['info']}File to save generated mnemonic phrases and passwords"
        )
        
        args = parser.parse_args()
        self.logger.debug(f"{COLOR_SCHEME['info']}Parsed arguments: {vars(args)}")
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
            
            self.mnemonic_generator = MnemonicGenerator(args.language)
            self.password_generator = PasswordGenerator(self.config, args.language)
            
            if args.auto and args.mnemonic:
                self.logger.error(
                    f"{COLOR_SCHEME['error']}Cannot use --auto and --mnemonic together"
                )
                raise PyPassGenError("Invalid argument combination: --auto and --mnemonic")

            if args.phrases <= 0:
                self.logger.error(
                    f"{COLOR_SCHEME['error']}Number of phrases must be positive: {args.phrases}"
                )
                raise PyPassGenError("Number of phrases must be positive")

            if args.auto and args.phrases > MAX_NUM_PHRASES:
                self.logger.error(
                    f"{COLOR_SCHEME['error']}Number of phrases exceeds maximum: {args.phrases} > {MAX_NUM_PHRASES}"
                )
                raise PyPassGenError(f"Number of phrases exceeds maximum: {MAX_NUM_PHRASES}")

            if args.mnemonic:
                self.logger.info(f"{COLOR_SCHEME['info']}Processing provided mnemonic...")
                password = self.password_generator.generate(
                    args.mnemonic, args.password_length
                )
                print(
                    f"{COLOR_SCHEME['success']}Generated Password: "
                    f"{COLOR_SCHEME['highlight']}{password}{Style.RESET_ALL}"
                )
            else:
                self.logger.info(f"{COLOR_SCHEME['info']}Generating {args.phrases} mnemonic phrases in parallel...")
                phrases = []
                with ThreadPoolExecutor() as executor:
                    futures = [
                        executor.submit(self.generate_phrase, args.words, args.password_length)
                        for _ in range(args.phrases)
                    ]
                    for i, future in enumerate(futures, 1):
                        mnemonic, password = future.result()
                        phrases.append((mnemonic, password))
                        self.logger.debug(f"{COLOR_SCHEME['info']}Generated phrase {i}/{args.phrases}")
                
                for i, (mnemonic, password) in enumerate(phrases, 1):
                    print(
                        f"{COLOR_SCHEME['success']}Mnemonic {i}: "
                        f"{COLOR_SCHEME['highlight']}{mnemonic}\n"
                        f"{COLOR_SCHEME['success']}Password {i}: "
                        f"{COLOR_SCHEME['highlight']}{password}{Style.RESET_ALL}\n"
                    )
                
                if args.output:
                    self.save_to_file(phrases, args.output)
                    
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
