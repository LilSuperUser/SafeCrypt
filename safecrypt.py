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
