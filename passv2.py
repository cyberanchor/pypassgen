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

def generate_mnemonic_phrases(num_phrases, words_per_phrase):
    mnemo = Mnemonic("english")  # Specify the language for the word list

    phrases = []
    try:
        for _ in range(num_phrases):
            # Generate a new mnemonic phrase
            phrase = mnemo.generate(strength=256)  # Use default strength (256 bits)

            # Split the generated phrase into a list of words
            words = phrase.split()

            # If the number of words per phrase is less than specified, raise an error
            if len(words) < words_per_phrase:
                raise ValueError(f"Generated phrase has only {len(words)} words, less than required {words_per_phrase} words.")

            # Take the first 'words_per_phrase' words to form the desired number of words per phrase
            final_phrase = " ".join(words[:words_per_phrase])

            phrases.append(final_phrase)
    except Exception as e:
        logging.error(f"Error occurred during mnemonic phrase generation: {e}")
        raise  # Re-raise the exception for higher-level handling

    return phrases

def write_phrases_to_file(phrases, output_file):
    try:
        with open(output_file, "w") as file:
            for phrase in phrases:
                file.write(phrase + "\n")
    except Exception as e:
        logging.error(f"Error occurred while writing phrases to file: {e}")
        raise  # Re-raise the exception for higher-level handling

def main():
    parser = argparse.ArgumentParser(
        description=f"{Fore.CYAN}Generate BIP 39 compatible mnemonic phrases and save to a file, or generate a password from a mnemonic phrase.{Style.RESET_ALL}",
        usage=f"{Fore.GREEN}%(prog)s [-p N] [-w {{12,15,18,21,24}}] [-o FILE] --mnemonic PHRASE --password-length N --use-symbols{Style.RESET_ALL}"
    )
    parser.add_argument(
        "-p", "--phrases", type=int, default=1,
        help=f"{Fore.YELLOW}Number of mnemonic phrases to generate (default: 1){Style.RESET_ALL}"
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
        "--mnemonic", type=str, default=None,
        help=f"{Fore.YELLOW}Mnemonic phrase to generate a password from{Style.RESET_ALL}"
    )
    parser.add_argument(
        "--password-length", type=int, default=12,
        help=f"{Fore.YELLOW}Length of the password to generate (default: 12){Style.RESET_ALL}"
    )
    parser.add_argument(
        "--use-symbols", action='store_true', 
        help=f"{Fore.YELLOW}Include symbols in the generated password{Style.RESET_ALL}"
    )

    args = parser.parse_args()

    num_phrases = args.phrases
    words_per_phrase = args.words
    output_file = args.output
    mnemonic_phrase = args.mnemonic
    password_length = args.password_length
    use_symbols = args.use_symbols

    # Initialize colorama for cross-platform ANSI color support
    init()

    # Configure logging
    logging.basicConfig(level=logging.INFO, format="%(asctime)s - %(levelname)s - %(message)s")

    try:
        if mnemonic_phrase:
            # Generate password from provided mnemonic phrase
            if not is_valid_mnemonic_phrase(mnemonic_phrase):
                raise ValueError("Invalid mnemonic phrase. Must be 12, 18, or 24 words.")
            
            logger = logging.getLogger(__name__)
            logger.setLevel(logging.INFO)

            # Create console handler and set formatter with color formatting
            console_handler = logging.StreamHandler()
            console_handler.setFormatter(logging.Formatter(Fore.CYAN + Style.BRIGHT + "[%(levelname)s] %(message)s"))
            logger.addHandler(console_handler)

            logger.info(Fore.YELLOW + f"Generating password from mnemonic phrase: '{mnemonic_phrase}'...")
            logger.info(Fore.YELLOW + f"Desired password length: {password_length} characters.")
            
            password = generate_password_from_mnemonic(mnemonic_phrase, password_length=password_length, use_symbols=use_symbols)
            print("Generated Password:", password)
        
        else:
            # Generate mnemonic phrases
            mnemonic_phrases = generate_mnemonic_phrases(num_phrases, words_per_phrase)

            if output_file:
                # Write generated mnemonic phrases to the specified output file
                write_phrases_to_file(mnemonic_phrases, output_file)
                logging.info(f"{Fore.GREEN}Generated {num_phrases} mnemonic phrases with {words_per_phrase} words per phrase.{Style.RESET_ALL}")
                logging.info(f"{Fore.GREEN}Saved to: {output_file}{Style.RESET_ALL}")
            else:
                # Print generated mnemonic phrases to the console with custom coloring
                for idx, phrase in enumerate(mnemonic_phrases):
                    words = phrase.split()
                    first_word = words[0]
                    rest_of_phrase = " ".join(words[1:])

                    # Determine colors for the first word and the rest of the phrase
                    first_word_color = Fore.GREEN
                    rest_color = Fore.MAGENTA if idx % 2 == 0 else Fore.CYAN

                    # Print the first word in green and the rest of the phrase in alternating colors
                    print(f"{first_word_color}{first_word}{Style.RESET_ALL} {rest_color}{rest_of_phrase}{Style.RESET_ALL}")

    except ValueError as ve:
        print(Fore.RED + f"ValueError: {ve}")
    except Exception as e:
        logging.exception(f"{Fore.RED}An error occurred: {e}{Style.RESET_ALL}")

if __name__ == "__main__":
    import sys
    if len(sys.argv) == 1:
        # Display help if no arguments are provided
        print(f"{Fore.YELLOW}Usage: python combined_script.py [-p N] [-w {{12,15,18,21,24}}] [-o FILE] --mnemonic PHRASE --password-length N --use-symbols{Style.RESET_ALL}")
        print(f"{Fore.YELLOW}Try 'python combined_script.py --help' for more options.{Style.RESET_ALL}")
        sys.exit(1)
    
    main()

