# SafeCrypt
A Python-based utility tool for secure encryption and file management.

## Overview
This Python script provides functionality to encrypt and decrypt:
- Messages
- Files
- Directories

using **Fernet symmetric encryption** from the `Cryptography` library.

It also provides functionality to shred files and directories.

## Features
- Encrypt/Decrypt text messages.
- Encrypt/Decrypt individual files.
- Encrypt/Decrypt all the files in a directory.
- Shred a file/directories so that it can't be recovered.
- Option to generate new encryption keys or load existing ones.
- Simple Command-line-interface.
- ANSI color-coded terminal output for better UX.
- Warning for existing files before overwriting them.
- Optional output files for encrypted/decrypted files.
- Log information about encrypted/decrypted files and directories
- Error handling and user friedly prompts.

## Requirements
To use this script you will need these installed on your system:
- Python 3.x
- `cryptography` Library for encryption and decryption.

## Usage
### Running the script:
Please use a terminal which can show colors as they can typically support `ANSI escape codes`
```
git clone https://github.com/LilSuperUser/SafeCrypt.git
cd SafeCrypt
pip install -r requirements.txt
chmod +x ./safecrypt.py
./safecrypt.py
```
### Menu options:
1. Encrypt a message:
    Enter a message and the script will encrypt it using loaded/generated key.

2. Encrypt a file:
    Provide the name of the file/path to the file to encrypt it in place/save to a new file.

3. Encrypt a directory:
    Provide the path to a directory and all files within it will be encrypted but Sub-directories will be skipped.

4. Decrypt a message:
    Enter an encrypted message and the script will decrypt it using the key you provide.

5. Decrypt a file:
    Provide the name of the file/path to the file to decrypt it in place/save to a new file.

6. Decrypt a directory:
    Provide the path to an encrypted directory and all files within it will be decrypted.

7. Shred a file:
    Shred a file ==> Delete a file such that it can't be recovered.

8. Shred a directory:
    Shred all files and sub directories present in a directory.

### Key management:
The script currently provides the following key management options:
- Generate a new key:
    Generates a new key and saves it to a file of user's choice.
- Load an existing key:
    Loads an existing eky from a file fo user's choice.

**Important**: Make sure to store your keys securely, as losing them will make it impossible to decrypt your encrypted messages or files.

## Planned Features
- Add a GUI.
- Progress bar for directory encryption/decryption.
- Multi-threaded file processing for faster encryption/decryption.
- Password-based encryption (PBKDF2).
- Compression of files before encryption.
- File integrity verification using hash checks.

## License
This project is licensed under the GNU General Public License v3.0 - see the [LICENSE](./LICENSE) file for details.
