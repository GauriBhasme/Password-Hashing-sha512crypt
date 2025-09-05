#!/usr/bin/env python3

# USAGE : ./bcrypt_hash.py -p mysecret
import bcrypt
import argparse
import sys

def main():
    parser = argparse.ArgumentParser(description="Generate bcrypt hash from a given password.")
    parser.add_argument(
        '-p', '--password',
        type=str,
        required=True,
        help='Password to hash (required)'
    )
    parser.add_argument(
        '-c', '--cost',
        type=int,
        default=12,
        help='Bcrypt cost factor (default: 12)'
    )
    args = parser.parse_args()

    # Ensure cost is within bcrypt's valid range
    if not (4 <= args.cost <= 31):
        print("Error: Bcrypt cost factor must be between 4 and 31.", file=sys.stderr)
        sys.exit(1)

    # Hash the password
    password_bytes = args.password.encode('utf-8')
    salt = bcrypt.gensalt(rounds=args.cost)
    hashed = bcrypt.hashpw(password_bytes, salt)

    # Output result
    print(f"{hashed.decode()}")

if __name__ == "__main__":
    main()
