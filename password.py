import mnemonic
import hashlib
import logging
import time
from colorama import init, Fore, Style

# Initialize colorama for cross-platform colored output
init(autoreset=True)

def is_valid_mnemonic_phrase(mnemonic_phrase):
    """Check if the provided mnemonic phrase is valid."""
    valid_lengths = [12, 18, 24]
    word_count = len(mnemonic_phrase.split())
    return word_count in valid_lengths

def generate_password_from_mnemonic(mnemonic_phrase, password_length=12, use_symbols=True):
    logger = logging.getLogger(__name__)

    # Validate mnemonic phrase
    if not is_valid_mnemonic_phrase(mnemonic_phrase):
        logger.error(Fore.RED + "Invalid mnemonic phrase. Must be 12, 18, or 24 words.")
        raise ValueError("Mnemonic phrase must be 12, 18, or 24 words.")

    # Generate seed from mnemonic phrase using BIP39 seed derivation
    logger.info(Fore.GREEN + "Generating seed from mnemonic phrase using BIP39...")
    seed = mnemonic.Mnemonic.to_seed(mnemonic_phrase)

    # Use PBKDF2-HMAC-SHA512 to derive a secure key
    logger.info(Fore.GREEN + "Deriving secure key using PBKDF2-HMAC-SHA512...")
    key = hashlib.pbkdf2_hmac('sha512', seed, b'password', 8192)

    # Determine character set for password
    characters = "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789"
    if use_symbols:
        characters += "!@#$%^&*()_+-=[]{};:,.<>?~"

    # Generate password character-by-character using PBKDF2-HMAC-SHA512
    logger.info(Fore.GREEN + f"Generating password of length {password_length} characters...")
    start_time = time.time()  # Start timing password generation
    password = []
    try:
        while len(password) < password_length:
            index = int.from_bytes(
                hashlib.pbkdf2_hmac('sha512', key, str(len(password)).encode(), 1000000), 'big'
            ) % len(characters)
            password.append(characters[index])
    except Exception as e:
        logger.error(Fore.RED + f"Error generating password: {e}")
        raise

    end_time = time.time()  # End timing password generation
    logger.info(Fore.GREEN + f"Password generated successfully in {end_time - start_time:.6f} seconds.")
    return ''.join(password)

# Example usage
mnemonic_phrase = "drama coral never fluid require pole attend liar fun hammer hurt match update scare garbage pluck scrap valve catch primary basic borrow believe safe"
password_length = 32

try:
    logger = logging.getLogger(__name__)
    logger.setLevel(logging.INFO)

    # Create console handler and set formatter with color formatting
    console_handler = logging.StreamHandler()
    console_handler.setFormatter(logging.Formatter(Fore.CYAN + Style.BRIGHT + "[%(levelname)s] %(message)s"))
    logger.addHandler(console_handler)

    logger.info(Fore.YELLOW + f"Generating password from mnemonic phrase: '{mnemonic_phrase}'...")
    logger.info(Fore.YELLOW + f"Desired password length: {password_length} characters.")
    
    if not is_valid_mnemonic_phrase(mnemonic_phrase):
        raise ValueError("Invalid mnemonic phrase. Must be 12, 18, or 24 words.")
    
    password = generate_password_from_mnemonic(mnemonic_phrase, password_length=password_length, use_symbols=True)
    print("Generated Password:", password)
except ValueError as ve:
    print(Fore.RED + f"ValueError: {ve}")
except Exception as e:
    print(Fore.RED + f"An unexpected error occurred: {e}")

