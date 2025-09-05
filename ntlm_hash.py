#! /usr/bin/python3

## USAGE : python ntlm_hash.py --password Password123

import argparse
from passlib.hash import nthash
import getpass

def main():
    parser = argparse.ArgumentParser(description="Generate NTLM hash from password")
    parser.add_argument(
        '-p', '--password',
        type=str,
        help='Password to hash (optional; if not provided, will prompt)'
    )
    args = parser.parse_args()

    # Get password either from argument or prompt
    if args.password:
        password = args.password
    else:
        password = getpass.getpass("Enter password: ")

    # Generate NTLM hash
    hashed = nthash.hash(password)

    # Output
    print(f"{hashed}")

if __name__ == "__main__":
    main()
