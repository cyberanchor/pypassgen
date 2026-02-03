import argparse
import hashlib
import logging
import time
from mnemonic import Mnemonic
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
    seed = Mnemonic.to_seed(mnemonic_phrase)

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

def main():
    parser = argparse.ArgumentParser(
        description=f"{Fore.CYAN}Generate BIP 39 compatible mnemonic phrases and save to a file, or generate a password from a mnemonic phrase.{Style.RESET_ALL}",
        usage=f"{Fore.GREEN}%(prog)s [--mnemonic PHRASE] | [--auto] [-p N] [-w {{12,15,18,21,24}}] [-o FILE] [--password-length N] [--use-symbols]{Style.RESET_ALL}",
        formatter_class=argparse.RawDescriptionHelpFormatter
    )
    parser.add_argument(
        "-p", "--phrases", type=int, default=1,
        help=f"{Fore.YELLOW}Number of mnemonic phrases and passwords to generate (default: 1){Style.RESET_ALL}"
    )
    parser.add_argument(
        "-w", "--words", type=int, default=12, choices=[12, 15, 18, 21, 24],
        help=f"{Fore.YELLOW}Number of words per phrase (choices: 12, 15, 18, 21, 24; default: 12){Style.RESET_ALL}"
    )
    parser.add_argument(
        "-o", "--output", type=str, default=None,
        help=f"{Fore.YELLOW}Output file to save generated phrases{Style.RESET_ALL}"
    )
    parser.add_argument(
        "--password-length", type=int, default=12,
        help=f"{Fore.YELLOW}Length of the password to generate (default: 12){Style.RESET_ALL}"
    )
    parser.add_argument(
        "--use-symbols", action='store_true', 
        help=f"{Fore.YELLOW}Include symbols in the generated password{Style.RESET_ALL}"
    )
    parser.add_argument(
        "--auto", action='store_true', 
        help=f"{Fore.YELLOW}Automatically generate mnemonic phrases and passwords{Style.RESET_ALL}"
    )
    parser.add_argument(
        "--mnemonic", type=str, default=None,
        help=f"{Fore.YELLOW}Use an existing mnemonic phrase to generate a password{Style.RESET_ALL}"
    )

    args = parser.parse_args()

    num_phrases = args.phrases
    words_per_phrase = args.words
    output_file = args.output
    password_length = args.password_length
    use_symbols = args.use_symbols
    auto_generate = args.auto
    mnemonic_phrase = args.mnemonic

    # Initialize colorama for cross-platform ANSI color support
    init()

    # Configure logging
    logging.basicConfig(level=logging.INFO, format="%(asctime)s - %(levelname)s - %(message)s")

    try:
        if auto_generate and mnemonic_phrase:
            raise ValueError("Options --auto and --mnemonic cannot be used simultaneously.")

        if mnemonic_phrase:
            # Generate password from provided mnemonic phrase
            password = generate_password_from_mnemonic(mnemonic_phrase, password_length=password_length, use_symbols=use_symbols)
            print(f"{Fore.YELLOW}Generated Password: {password}{Style.RESET_ALL}")

        elif auto_generate:
            # Automatically generate mnemonic phrases and passwords
            generated_phrases = []
            for _ in range(num_phrases):
                mnemonic_phrase = Mnemonic("english").generate(strength=256)
                password = generate_password_from_mnemonic(mnemonic_phrase, password_length=password_length, use_symbols=use_symbols)
                generated_phrases.append((mnemonic_phrase, password))

            # Print generated phrases and passwords
            for phrase, password in generated_phrases:
                print(f"{Fore.YELLOW}Mnemonic Phrase: {phrase} - Password: {password}{Style.RESET_ALL}")

        else:
            # Generate mnemonic phrases
            mnemonic_phrases = []
            for _ in range(num_phrases):
                mnemonic_phrase = Mnemonic("english").generate(strength=256)
                password = generate_password_from_mnemonic(mnemonic_phrase, password_length=password_length, use_symbols=use_symbols)
                mnemonic_phrases.append((mnemonic_phrase, password))

            if output_file:
                # Write generated mnemonic phrases to the specified output file
                with open(output_file, "w") as file:
                    for phrase, _ in mnemonic_phrases:
                        file.write(phrase + "\n")
                logging.info(f"{Fore.GREEN}Generated {num_phrases} mnemonic phrases with {words_per_phrase} words per phrase.{Style.RESET_ALL}")
                logging.info(f"{Fore.GREEN}Saved to: {output_file}{Style.RESET_ALL}")
            else:
                # Print generated mnemonic phrases to the console with custom coloring
                for phrase, _ in mnemonic_phrases:
                    print(f"{Fore.YELLOW}Mnemonic Phrase: {phrase}{Style.RESET_ALL}")

    except ValueError as ve:
        print(Fore.RED + f"ValueError: {ve}")
    except Exception as e:
        logging.exception(f"{Fore.RED}An error occurred: {e}{Style.RESET_ALL}")

# Execute the main function if the script is run directly
if __name__ == "__main__":
    main()
