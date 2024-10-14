# safecrypt.py is a python script which uses fernet symmetric encryption to encrypt/decrypt messages, files, directories
#!usr/bin/env python3
'''
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
'''

from cryptography.fernet import Fernet
from os.path import exists, isdir, join
import os
import sys

# ANSI escape codes for colored texts
RED = '\033[91m' # for errors and warnings
RESET = '\033[0m' # to reset the color back to normal
GREEN = '\033[92m' # for succeses
CYAN = '\033[96m' # for enc and dec messages
MAGENTA = '\033[95m' # for menus

# function to generate a new key
def gen_key(kname: str) -> bytes:
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
                kfile.write(key)
            print(f"{GREEN}Successfully overwritten {kname} with a new key{RESET}")
            return key
        else:
            # Create new key if file does not exist
            key = Fernet.generate_key()
            with open(kname, 'wb') as kfile:
                kfile.write(key)
            print(f"{GREEN}Successfully created a new key file: {kname}{RESET}")
            return key
    except Exception as e:
        sys.exit(f"{RED}Error during generating the key: {e}{RESET}")

# function to load key from a file
def load_key(kname: str) -> bytes:
    try:
        if not exists(kname):
            sys.exit(f"{RED}Error: File {kname} does not exist!{RESET}")
        with open(kname, 'rb') as kfile:
            return kfile.read()
    except Exception as e:
        sys.exit(f"{RED}Error during loading the key: {e}{RESET}")

# function to return fernet object for enc
def fernet_giver_enc() -> object:
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

# function to return fernet object for dec
def fernet_giver_dec() -> object:
    try:
        kname = input("\nEnter the name for the key file: ")
        if not exists(kname):
            sys.exit(f"{RED}Error: File {kname} doesn't exist{RESET}")

        fernet = Fernet(load_key(kname))
        print(f"{GREEN}Successfully loaded key from {kname} {RESET}")
        return fernet
    except Exception as e:
        sys.exit(f"{RED}Error during returning fernet object: {e}{RESET}")

# function to encrypt a message
def msg_encrypter(msg: str, fernet: object) -> str:
    try:
        enc_msg = fernet.encrypt(msg.encode(encoding = "utf-8", errors = "strict"))
        return enc_msg.decode(encoding = "utf-8", errors = "strict")
    except Exception as e:
        sys.exit(f"{RED}Error during encrypting message: {e}{RESET}")

# function to encrypt a file
def file_encrypter(fname: str, fernet: object) -> None:
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

# function to encrypt all the files present in a given dir
def dir_encrypter(dname: str, fernet: object) -> None:
    try:
        if not os.path.isdir(dname):
            sys.exit(f"{RED}Error: Directory {dname} does not exist!")

        counter = 0
        enc_files = []
        encountered_dirs = []
        print()
        for path, dirs, files in os.walk(dname):
            encountered_dirs.append(path)
            for file in (files):
                file_path = join(path, file)
                print(f"{GREEN}Encrypting file: {RESET}{file_path}")

                with open(file_path, 'rb') as f:
                    data = f.read()
                    enc_data = fernet.encrypt(data)

                with open(file_path, 'wb') as f:
                    f.write(enc_data)

                enc_files.append(file_path)
                counter += 1

        print(f"{GREEN}\nLogs:{RESET}")
        print(f"{GREEN}    Directory targeted: {RESET}{dname}")
        print(f"{GREEN}    Total number of files encrypted: {RESET}{counter}")
        print(f"{GREEN}    Files that were encrypted{RESET}:")
        for ef in enc_files:
            print(f"        - {ef}")

        if encountered_dirs:
            encountered_dirs.pop(0)
            print(f"{GREEN}    Subdirectories encountered (but not processed){RESET}:")
            for ed in encountered_dirs:
                print(f"        - {ed}")
        else:
            print(f"{GREEN}    No subdirectories were present in {RESET}: {dname}")

    except Exception as e:
        sys.exit(f"{RED}Error during encrypting files in dir {dname}: {e}{RESET}")

# function to decrypt a message
def msg_decrypter(msg: str, fernet: object) -> str:
    try:
        dec_msg = fernet.decrypt(msg.encode(encoding = "utf-8", errors = "strict"))
        return dec_msg.decode(encoding = "utf-8", errors = "strict")
    except Exception as e:
        sys.exit(f"Error during decrypting message: {e}")

# function to decrypt a file
def file_decrypter(fname: str, fernet: object) -> None:
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

# function to decrypt all the files in a given dir
def dir_decrypter(dname: str, fernet:object) -> None:
    try:
        if not os.path.isdir(dname):
            sys.exit(f"{RED}Error: Directory {dname} does not exist!")

        counter = 0
        dec_files = []
        encountered_dir = []
        print()
        for path, dirs, files in os.walk(dname):
            encountered_dir.append(path)
            for file in (files):
                file_path = join(path, file)
                print(f"{GREEN}Decrypting file: {RESET}{file_path}")

                with open(file_path, 'rb') as f:
                    enc_data = f.read()
                    data = fernet.decrypt(enc_data)

                with open(file_path, 'wb') as f:
                    f.write(data)

                dec_files.append(file_path)
                counter += 1

        print(f"{GREEN}\nLogs:{RESET}")
        print(f"{GREEN}    Directory targeted: {RESET}{dname}")
        print(f"{GREEN}    Total number of files decrypted: {RESET}{counter}")
        print(f"{GREEN}    Files that were decrypted{RESET}:")
        for df in dec_files:
            print(f"        - {df}")

        if encountered_dir:
            encountered_dir.pop(0)
            print(f"{GREEN}    Subdirectories encountered (but not processed){RESET}:")
            for ed in encountered_dir:
                print(f"        - {ed}")
        else:
            print(f"{GREEN}    No subdirectories were present in {RESET}: {dname}")

    except Exception as e:
        sys.exit(f"{RED}Error during decrypting files in dir {dname}: {e}{RESET}")

# function to shred a given file by a given level
def shredder(fname: str, level: int) -> None:
    try:
        if not exists(fname):
            sys.exit(f"{RED}Error: File {fname} does not exist!")
        
        response = input(f"{RED}Warning: {fname} will be shredded. Do you wish to proceed? (y|n): {RESET}").lower()

        if response == 'y':
            # Capture the file size before opening in write mode
            file_size = os.path.getsize(fname)
            
            # Overwrite the file with random data
            with open(fname, 'wb+') as f:
                for i in range(level):
                    f.seek(0)  # Seek to the beginning of the file
                    f.write(os.urandom(file_size))  # Write random data

            # Remove the file after overwriting
            os.remove(fname)
            print(f"{GREEN}Successfully shredded the file {fname} {RESET}")

        elif response == 'n':
            sys.exit(f"{GREEN}Operation cancelled by user{RESET}")

        else:
            sys.exit(f"{RED}Error: Invalid choice{RESET}")
    except Exception as e:
        print(f"{RED}Error during shredding file: {e}")

# function to shred a directory
def dir_shredder(dname: str, level: int) -> None:
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
            for Path, dirs, files in os.walk(dname, topdown=False):
                for file in files:
                    fpath = join(Path, file)
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
                    dir_path = join(Path, dir)
                    print(f"{GREEN}Removing directory: {RESET}{dir_path}")
                    os.rmdir(dir_path)  # Remove empty subdirectories
                    shred_dirs.append(dir_path)
                    d_counter+=1

            # Finally, remove the top-level directory
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

############################################################################################################################
if __name__ == "__main__":
    try:
        if os.name == 'nt':            
            os.system("cls")
        else:
            os.system("clear")
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
        print(" 4 --> Decrypt a message")
        print(" 5 --> Decrypt a file")
        print(" 6 --> Decrypt a directory")
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
    print("The script is to be run directly and not imported!")
