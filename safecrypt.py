#!usr/bin/env python3

# safecrypt.py is a python script which uses fernet symmetric encryption
# to encrypt/decrypt messages, files & directories
"""
Copyright (C) 2024 LilSuperUser/Tanmay

This program is free software: you can redistribute it and/or modify
it under the terms of the GNU General Public License as published by
the Free Software Foundation, either version 3 of the License, or
(at your option) any later version.

This program is distributed in the hope that it will be useful,
but WITHOUT ANY WARRANTY; without even the implied warranty of
MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
GNU General Public License for more details.

You should have received a copy of the GNU General Public License
along with this program.  If not, see <https://www.gnu.org/licenses/>.
"""

import sys
import os
from os.path import exists, isdir, join
from cryptography.fernet import Fernet

# ANSI escape codes for colored texts
RED = "\033[91m"        # For errors and warnings
RESET = "\033[0m"       # To reset the color back to normal
GREEN = "\033[92m"      # For succeses
CYAN = "\033[96m"       # For enc and dec messages
MAGENTA = "\033[95m"    # For menus


def gen_key(kname: str) -> bytes:
    '''
    Function to generate a new key and store it in a file.
    Asks user to overwrite the file if the file already exists.
    '''
    try:
        if exists(kname):
            response = input(f"{RED}Warning: {kname} already exists, overwrite it? (y|n): {RESET}").lower()
            if response == 'n':
                sys.exit(f"{GREEN}Operation canceled by user.{RESET}")
            elif response != 'y':
                sys.exit(f"{RED}Error: Invalid choice{RESET}")

            # Overwrite key if user confirms
            key = Fernet.generate_key()
            with open(kname, 'wb') as kfile:
                _ = kfile.write(key)
            print(f"{GREEN}Successfully overwritten {kname} with a new key{RESET}")
            return key
        else:
            # Create new key if file does not exist
            key = Fernet.generate_key()
            with open(kname, 'wb') as kfile:
                _ = kfile.write(key)
            print(f"{GREEN}Successfully created a new key file: {kname}{RESET}")
            return key
    except Exception as e:
        sys.exit(f"{RED}Error during generating the key: {e}{RESET}")


def load_key(kname: str) -> bytes:
    '''
    Function to load the key from the file given.
    '''
    try:
        if not exists(kname):
            sys.exit(f"{RED}Error: File {kname} does not exist!{RESET}")
        with open(kname, 'rb') as kfile:
            return kfile.read()
    except Exception as e:
        sys.exit(f"{RED}Error during loading the key: {e}{RESET}")


def fernet_giver_enc() -> object:
    '''
    Function to return the fernet object for encryption.
    Enables user to either generate a new key or load the key from a file.
    '''
    try:
        print()
        print(f"{MAGENTA}1 --> Generate a new key")
        print(f"2 --> Load the key from a file{RESET}")
        enc_choice = int(input("choose: "))

        if enc_choice == 1:
            kname = input("\nEnter the name for the key file: ")
            fernet = Fernet(gen_key(kname))
            return fernet

        elif enc_choice != 2:
            sys.exit(f"{RED}Error: Invalid choice{RESET}")

        kname = input("\nEnter the name for the key file: ")
        fernet = Fernet(load_key(kname))
        print(f"{GREEN}Successfully loaded key from {kname}{RESET}")
        return fernet

    except Exception as e:
        sys.exit(f"{RED}Error during returning fernet object: {e}{RESET}")


def fernet_giver_dec() -> object:
    '''
    Function to return the fernet object for decryption
    '''
    try:
        kname = input("\nEnter the name for the key file: ")
        if not exists(kname):
            sys.exit(f"{RED}Error: File {kname} doesn't exist{RESET}")

        fernet = Fernet(load_key(kname))
        print(f"{GREEN}Successfully loaded key from {kname} {RESET}")
        return fernet

    except Exception as e:
        sys.exit(f"{RED}Error during returning fernet object: {e}{RESET}")


def msg_encrypter(msg: str, fernet: object) -> str:
    '''
    Function that takes two arguments:
        - string to encrypt
        - fernet object to encrypt the string with
    Returns the encrypted string encoded as utf-8
    '''
    try:
        enc_msg = fernet.encrypt(msg.encode(encoding = "utf-8", errors = "strict"))
        return enc_msg.decode(encoding = "utf-8", errors = "strict")
    except Exception as e:
        sys.exit(f"{RED}Error during encrypting message: {e}{RESET}")


def file_encrypter(fname: str, fernet: object) -> None:
    '''
    Function that takes two arguments:
        - fname to encrypt
        - fernet object to encryp the file with
    Asks user for the output file name, if none is provided, uses the input file name
    warns user that the oputfile already exists and asks to overwrite it.
    Returns nothing
    '''
    try:
        if not exists(fname):
            sys.exit(f"{RED}Error: File {fname} doesn't exist!{RESET}")

        # reading original file
        with open(fname, 'rb') as f:
            data = f.read()
            enc_data = fernet.encrypt(data)

        # ask user for output file path/name
        output_fname = input(f"Enter the name/path for the output file (leave blank to overwrite {fname}): ").strip()
        if not output_fname:
            output_fname = fname

        # check if the output file exists
        if exists(output_fname) and output_fname != fname:
            response = input(f"{RED}Warning: {output_fname} already exists. Overwrite it? (y|n): {RESET}").lower()
            if response != 'y':
                if response == 'n':
                    sys.exit("{GRN}Operation canceled{RST}")
                else:
                    sys.exit("{RED}Error: Invalid choice{RST}")

        # write encrypted data to the chosen file
        with open(output_fname, 'wb') as f:
            f.write(enc_data)

        if output_fname == fname:
            print(f"{GREEN}{fname} has been successfully encrypted{RESET}")
        else:
            print(f"{GREEN}Created new file {output_fname} with encrypted data from {fname}{RESET}")

    except Exception as e:
        sys.exit(f"{RED}Error during encryption: {e}{RESET}")


def msg_decrypter(msg: str, fernet: object) -> str:
    '''
    Function that takes two arguments:
        - string to decrypt
        - fernet object to decrypt the string with
    Returns the decrypted string decoded as utf-8
    '''
    try:
        dec_msg = fernet.decrypt(msg.encode(encoding = "utf-8", errors = "strict"))
        return dec_msg.decode(encoding = "utf-8", errors = "strict")
    except Exception as e:
        sys.exit(f"Error during decrypting message: {e}")


if __name__ == "__main__":
    try:
        if os.name == 'nt':
            _ = os.system("cls")
        else:
            _ = os.system("clear")
        print(f'''{GREEN}
    ________________________________________________________________________
    |                                                                       |
    |Copyright (C) 2024 LilSuperUser/Tanmay                                 |
    |                                                                       |
    |This program is free software: you can redistribute it and/or modify   |
    |it under the terms of the GNU General Public License as published by   |
    |the Free Software Foundation, either version 3 of the License, or      |
    |(at your option) any later version.                                    |
    |                                                                       |
    |This program is distributed in the hope that it will be useful,        |
    |but WITHOUT ANY WARRANTY; without even the implied warranty of         |
    |MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the          |
    |GNU General Public License for more details.                           |
    |                                                                       |
    |You should have received a copy of the GNU General Public License      |
    |along with this program.  If not, see <https://www.gnu.org/licenses/>. |
    |_______________________________________________________________________|
    {RESET}''')

        print(f"{MAGENTA}Menu:")
        print(" 1 --> Encrypt a message")
        print(" 2 --> Encrypt a file")
        print(" 3 --> Encrypt a directory")
        print()
        print(" 4 --> Decrypt a message")
        print(" 5 --> Decrypt a file")
        print(" 6 --> Decrypt a directory")
        print()
        print(" 7 --> Shred a file")
        print(" 8 --> Shred a directory")
        print(f" 0 --> Exit{RESET}")
        menu_choice = int(input(("Choose from the options given above: ")))

        if menu_choice == 0:
            sys.exit(f"{GREEN}Exitting the program...{RESET}")

        elif menu_choice == 1:
            fernet = fernet_giver_enc()
            msg = input("\nEnter the message that you want to encrypt: ")
            print(f"\nThe encrypted message is:\n{CYAN}{msg_encrypter(msg, fernet)}{RESET}")

        elif menu_choice == 2:
            fernet = fernet_giver_enc()
            fname = input("\nEnter file name or path to the file that you want to encrypt: ")
            file_encrypter(fname, fernet)

        elif menu_choice == 4:
            fernet = fernet_giver_dec()
            msg = input("\nEnter the message that you want to decrypt: ")
            print(f"\nThe decrypted message is:\n{CYAN}{msg_decrypter(msg, fernet)}{RESET}")



    except Exception as e:
        sys.exit(f"{RED}Error during choosing from above: {e}{RESET}")
