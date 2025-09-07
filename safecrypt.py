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


def dir_encrypter(dname: str, fernet: object) -> None:
    '''
    Function to encrypt all the files present in the given directory.
    Takes two argumetns:
        - dname: str (name of the directory to encrypt)
        - fernet: obj (fernet object to encrypt the files with)
    If subdirectories are present in the given directory, they are skipped.
    At last, the logs are printed.
    '''
    try:
        if not os.path.isdir(dname):
            sys.exit(f"{RED}Error: Directory {dname} does not exist!{RESET}")

        counter = 0
        enc_files = []
        encountered_dirs = []

        print()
        with os.scandir(dname) as entries:
            for entry in entries:
                if entry.is_file():
                    file_path = entry.path
                    print(f"{GREEN}Encrypting file: {RESET}{file_path}")

                    with open(file_path, 'rb') as f:
                        data = f.read()
                        enc_data = fernet.encrypt(data)

                    with open(file_path, 'wb') as f:
                        f.write(enc_data)

                    enc_files.append(file_path)
                    counter += 1
                elif entry.is_dir():
                    encountered_dirs.append(entry.path)

        print(f"{GREEN}\nLogs:{RESET}")
        print(f"{GREEN}    Directory targeted: {RESET}{dname}")
        print(f"{GREEN}    Total number of files encrypted: {RESET}{counter}")
        print(f"{GREEN}    Files that were encrypted:{RESET}")
        for ef in enc_files:
            print(f"        - {ef}")

        if encountered_dirs:
            print(f"{GREEN}    Subdirectories encountered (but not processed):{RESET}")
            for ed in encountered_dirs:
                print(f"        - {ed}/")
        else:
            print(f"{GREEN}    No subdirectories were present in: {RESET}{dname}")

    except Exception as e:
        sys.exit(f"{RED}Error during encrypting files in dir {dname}: {e}{RESET}")


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


def file_decrypter(fname: str, fernet: object) -> None:
    '''
    Function that takes two arguments:
        - fname to decrypt
        - fernet object to decrypt the file with
    Checks if the file already exists on the disk, exit if it doesn't and if it does
    then read the original content, decrypts it, ask for the output file name
    if no output file name is provided use the input file name to store the decrypted data
    '''
    try:
        if not exists(fname):
            sys.exit(f"{RED}Error: File {fname} doesn't exist!{RESET}")

        # reading original file
        with open(fname, 'rb') as f:
            enc_data = f.read()
            data = fernet.decrypt(enc_data)

        # ask user for output file path/name
        output_fname = input(f"Enter the name/path for the output file (leave blank to overwrite {fname}): ").strip()
        if not output_fname:
            output_fname = fname

        # check if the output file exists
        if exists(output_fname) and output_fname != fname:
            response = input(f"{RED}Warning: {output_fname} already exists. Overwrite it? (y|n): {RESET}").lower()
            if response != 'y':
                if response == 'n':
                    sys.exit(f"{RED}Operation canceled{RESET}")
                else:
                    sys.exit(f"{RED}Error: Invalid choice{RESET}")

        # write decrypted data to the chosen file
        with open(output_fname, 'wb') as f:
            f.write(data)

        if output_fname == fname:
            print(f"{GREEN}{fname} has been successfully decrypted.{RESET}")
        else:
            print(f"{GREEN}Created new file {output_fname} with decrypted data from {fname}{RESET}")

    except Exception as e:
        sys.exit(f"{RED}Error during decryption: {e}{RESET}")


def dir_decrypter(dname: str, fernet:object) -> None:
    '''
    Function to decrypt all the files present in the given directory.
    Takes two arguments:
        - dname: str (name of the directory to decrypt
        - fernet: obj (fernet object to decrypt the files with)
    If subdirectories are present in the given directory, they are skipped.
    At last, the logs are printed.
    '''
    try:
        if not os.path.isdir(dname):
            sys.exit(f"{RED}Error: Directory {dname} does not exist!{RESET}")

        counter = 0
        dec_files = []
        encountered_dirs = []

        print()
        with os.scandir(dname) as entries:
            for entry in entries:
                if entry.is_file():
                    file_path = entry.path
                    print(f"{GREEN}Decrypting file: {RESET}{file_path}")

                    with open(file_path, 'rb') as f:
                        enc_data = f.read()
                        data = fernet.decrypt(enc_data)

                    with open(file_path, 'wb') as f:
                        f.write(data)

                    dec_files.append(file_path)
                    counter += 1
                elif entry.is_dir():
                    encountered_dirs.append(entry.path)

        print(f"{GREEN}\nLogs:{RESET}")
        print(f"{GREEN}    Directory targeted: {RESET}{dname}")
        print(f"{GREEN}    Total number of files decrypted: {RESET}{counter}")
        print(f"{GREEN}    Files that were decrypted:{RESET}")
        for df in dec_files:
            print(f"        - {df}")

        if encountered_dirs:
            print(f"{GREEN}    Subdirectories encountered (but not processed):{RESET}")
            for ed in encountered_dirs:
                print(f"        - {ed}/")
        else:
            print(f"{GREEN}    No subdirectories were present in: {RESET}{dname}")

    except Exception as e:
        sys.exit(f"{RED}Error during decrypting files in dir {dname}: {e}{RESET}")


def shredder(fname: str, level: int) -> None:
    '''
    Function to shred a given file by a give level.
    Takes two arguments:
        - fname: str (name of the file to shred)
        - level: int (level of the shredding)
    Overwrites the file level number of times and then deletes it.
    '''
    try:
        if not exists(fname):
            sys.exit(f"{RED}Error: File {fname} does not exist!")

        response = input(f"{RED}Warning: {fname} will be shredded. Do you wish to proceed? (y|n): {RESET}").lower()

        if response == 'y':
            file_size = os.path.getsize(fname)

            with open(fname, 'wb+') as f:
                for i in range(level):
                    f.seek(0)
                    f.write(os.urandom(file_size))

            os.remove(fname)
            print(f"{GREEN}Successfully shredded the file {fname} {RESET}")

        elif response == 'n':
            sys.exit(f"{GREEN}Operation cancelled by user{RESET}")

        else:
            sys.exit(f"{RED}Error: Invalid choice{RESET}")

    except Exception as e:
        print(f"{RED}Error during shredding file: {e}")


def dir_shredder(dname: str, level: int) -> None:
    '''
    Function to shred a directory (recursively) by a given level.
    Takes two arguments:
        - dname: str (name of the directory to shred)
        - level: int (level of the shredding)
    Overwrites the directory, level number of times and then deletes it.
    '''
    try:
        if not isdir(dname):
            sys.exit(f"{RED}Error: Directory {dname} does not exist!")

        f_counter = 0
        d_counter = 0
        shred_files = []
        shred_dirs = []
        print()
        response = input(f"{RED}Warning: All files in {dname} will be shredded. Do you wish to proceed? (y|n): {RESET}").lower()
        if response == 'y':
            for path, dirs, files in os.walk(dname, topdown=False):
                for file in files:
                    fpath = join(path, file)
                    print(f"{GREEN}Shredding file: {RESET}{fpath}")
                    for i in range(level):
                        with open(fpath, 'wb') as f:
                            f.seek(0)
                            f.write(os.urandom(os.path.getsize(fpath)))
                            f.flush()
                    os.remove(fpath)
                    shred_files.append(fpath)
                    f_counter += 1

                for dir in dirs:
                    dir_path = join(path, dir)
                    print(f"{GREEN}Removing directory: {RESET}{dir_path}")
                    os.rmdir(dir_path)  # Remove empty subdirectories
                    shred_dirs.append(dir_path)
                    d_counter+=1

            os.rmdir(dname)

            # Print log information
            print(f"{GREEN}\nLogs:{RESET}")
            print(f"{GREEN}    Directory targeted: {RESET}{dname}")
            print(f"{GREEN}    Total number of files shredded: {RESET}{f_counter}")
            print(f"{GREEN}    Total number of sub-directories shredded: {RESET}{d_counter}")
            print(f"{GREEN}    Files that were shredded{RESET}:")
            for sf in shred_files:
                print(f"        - {sf}")
            print(f"{GREEN}    Sub-directories that were shredded{RESET}:")
            for sd in shred_dirs:
                print(f"        - {sd}")
        else:
            print(f"{GREEN}Operation canceled by user.{RESET}")

    except Exception as e:
        print(f"{RED}Error during shredding directory: {e}")


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

        elif menu_choice == 3:
            fernet = fernet_giver_enc()
            print(f"\n{RED}Warning: Make sure key file is not present in the directory that you give{RESET}")
            dname = input("Enter dir name or path of the dir that you want to encrypt: ")
            dir_encrypter(dname, fernet)

        elif menu_choice == 4:
            fernet = fernet_giver_dec()
            msg = input("\nEnter the message that you want to decrypt: ")
            print(f"\nThe decrypted message is:\n{CYAN}{msg_decrypter(msg, fernet)}{RESET}")

        elif menu_choice == 5:
            fernet = fernet_giver_dec()
            fname = input("\nEnter file name or path to the file that you want to decrypt: ")
            file_decrypter(fname, fernet)

        elif menu_choice == 6:
            fernet = fernet_giver_dec()
            print(f"\n{RED}Warning: Make sure key file is not present in the directory that you give{RESET}")
            dname = input("Enter dir name or path of the dir that you want to decrypt: ")
            dir_decrypter(dname, fernet)

        elif menu_choice == 7:
            fname = input("Enter file name or path to the file that you want to shred: ")
            level = int(input("Enter the level of shredding: "))
            shredder(fname, level)

        elif menu_choice == 8:
            print(f"\n{RED}Warning: Make nothing important is present in the directory that you give{RESET}")
            dname = input("Enter directory name or directory path that you want to shred: ")
            level = int(input("Enter the level of shredding: "))
            dir_shredder(dname, level)

        else:
            sys.exit(f"{RED}Error: Invalid choice{RESET}")

    except Exception as e:
        sys.exit(f"{RED}Error during choosing from above: {e}{RESET}")

else:
    print(f"{RED}The script is to be run directly and not imported!{RESET}")
