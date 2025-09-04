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
        print(" 4 --> Decrypt a message")
        print(" 5 --> Decrypt a file")
        print(" 6 --> Decrypt a directory")
        print(" 7 --> Shred a file")
        print(" 8 --> Shred a directory")
        print(f" 0 --> Exit{RESET}")
        menu_choice = int(input(("Choose from the options given above: ")))

        if menu_choice == 0:
            sys.exit(f"{GREEN}Exitting the program...{RESET}")

    except Exception as e:
        sys.exit(f"{RED}Error during choosing from above: {e}{RESET}")
