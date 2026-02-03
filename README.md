# PyPassGen

PyPassGen is a Python code that facilitates the generation of secure passwords from mnemonic phrases using BIP39 seed derivation and PBKDF2-HMAC-SHA512 key derivation. This code is designed to provide a reliable and efficient method for generating strong passwords based on mnemonic phrases, which are commonly used in cryptocurrency wallets and other secure applications.

![running on linux](https://github.com/jumb0t/pypassgen/blob/main/screenshot.png)


## Features

- **Mnemonic Phrase Validation**: Validate the format and length of BIP39 mnemonic phrases (12, 18, or 24 words).
  
- **Password Generation**: Generate cryptographically secure passwords from validated mnemonic phrases.
  
- **Customizable Password Length**: Specify the desired length of generated passwords (e.g., 12, 16, 24 characters).

- **Symbol Inclusion**: Option to include special symbols in generated passwords for increased complexity and security.

- **Secure Key Derivation**: Utilize BIP39 seed derivation and PBKDF2-HMAC-SHA512 key derivation to ensure cryptographic strength and randomness.

## Installation

To use PyPassGen, follow these steps:

1. Install Python (if not already installed) from [python.org](https://www.python.org/).
2. Install required Python libraries using pip:
   ```bash
   pip install mnemonic colorama
   ```

## Running Instructions on Linux

### Step 1: Install Python

If Python is not already installed on your Linux system, you can install it using the package manager. For example, on Debian-based systems (such as Ubuntu), use `apt`:
  ```bash
  sudo apt update
  sudo apt install python3
  ```
### Step 2: Clone the Project Repository

Clone the CryptoMnemonicPassword project repository from GitHub using git:
  ```bash
  git clone https://github.com/jumb0t/pypassgen
  cd pypassgen
  ```



### Step 3: Run Example Script

Navigate to the examples directory and run the example script to generate a password from a mnemonic phrase:

  ```bash
  cd examples
  python example_usage.py
  ```

This will execute the example_usage.py script, demonstrating how to use the CryptoMnemonicPassword library to generate passwords from mnemonic phrases.

### Step 4: Customize and Integrate

Integrate the CryptoMnemonicPassword library into your own Python projects by importing crypto_mnemonic_password and using the generate_password_from_mnemonic function with your desired parameters.

  ```bash
from crypto_mnemonic_password import generate_password_from_mnemonic

mnemonic_phrase = "example twelve word mnemonic phrase here"
password_length = 16
password = generate_password_from_mnemonic(mnemonic_phrase, password_length=password_length, use_symbols=True)
print("Generated Password:", password)
```
Adjust the `mnemonic_phrase`, `password_length`, and `use_symbols` parameters as needed for your specific use case.



# Running PyPassGen on Android with Termux

This guide demonstrates how to install and run the PyPassGen Python library on an Android device using Termux. PyPassGen allows you to generate secure passwords from mnemonic phrases using BIP39 seed derivation and PBKDF2-HMAC-SHA512 key derivation.

![running on android](https://github.com/jumb0t/pypassgen/blob/main/screenshot2.jpg)


## Prerequisites

Before proceeding, ensure you have the following prerequisites installed on your Android device:

- **Termux**: Install the Termux app from the [Google Play Store](https://play.google.com/store/apps/details?id=com.termux).
- **Python**: Install Python and pip within Termux for running Python scripts.

## Installation

1. **Install Termux**:
   - Download and install Termux from the Google Play Store.

2. **Update Packages**:
   - Launch Termux and update the package repository:
     ```bash
     pkg update && pkg upgrade
     ```

3. **Install Python and pip**:
   - Install Python and pip within Termux:
     ```bash
     pkg install python
     ```

4. **Install Required Libraries**:
   - Use pip to install the required Python libraries (`mnemonic` and `colorama`):
     ```bash
     pip install mnemonic colorama
     ```

5. **Clone the PyPassGen Repository**:
   - Clone the PyPassGen project repository from GitHub using `git`:
     ```bash
     pkg install git
     git clone https://github.com/jumb0t/pypassgen
     cd pypassgen
     ```

## Running PyPassGen

After completing the installation steps, you can run the PyPassGen library to generate passwords from mnemonic phrases.

1. **Navigate to the Project Directory**:
   - Change to the directory containing the PyPassGen files:
     ```bash
     cd pypassgen
     ```

2. **Run the Example Script**:
   - Execute the example script (`example_usage.py`) to generate a password from a mnemonic phrase:
     ```bash
     python example_usage.py
     ```

   This will demonstrate how to use the PyPassGen library on your Android device with Termux.

## Customization and Integration

You can customize the `mnemonic_phrase`, `password_length`, and other parameters in the example script (`example_usage.py`) to suit your specific requirements.

```python
from crypto_password_generator import generate_password_from_mnemonic

mnemonic_phrase = "example twelve word mnemonic phrase here"
password_length = 16
password = generate_password_from_mnemonic(mnemonic_phrase, password_length=password_length, use_symbols=True)
print("Generated Password:", password)
```



### License

This project is licensed under the MIT License. See the LICENSE file for details.
