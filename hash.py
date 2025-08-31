#!/usr/bin/env python3

import crypt
import getpass


def generate_sha512crypt(password, salt=None):
    """
    Generate a SHA512-crypt hash of a plaintext password.
    If no salt is provided, a random one will be generated.
    """
    if salt is None:
        # Generate a 16-character random salt (as used in /etc/shadow)
        salt = crypt.mksalt(crypt.METHOD_SHA512)
    else:
        # Ensure the salt starts with $6$ (SHA512-crypt identifier)
        if not salt.startswith('$6$'):
            salt = f'$6${salt}'

    # Generate the hash
    hashed = crypt.crypt(password, salt)
    return hashed


if __name__ == "__main__":
    print("[*] SHA512-crypt Hash Generator (Authorized Pentest Use Only)")

    # Input password securely (hidden input)
    password = getpass.getpass("Enter password to hash (input hidden): ").strip()
    if not password:
        print("[!] Password cannot be empty.")
        exit(1)

    # Optional: Custom salt (leave blank for random)
    salt_input = input("Optional: Enter custom salt (without $6$ prefix, or leave blank): ").strip()
    salt = f'$6${salt_input}' if salt_input else None

    # Generate and print the hash
    hashed_password = generate_sha512crypt(password, salt)
    print(f"\n[*] Generated SHA512-crypt Hash: {hashed_password}")
