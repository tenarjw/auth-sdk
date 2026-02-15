#!/usr/bin/env python3
import argparse
import mariadb
import bcrypt

parser = argparse.ArgumentParser(description="Change mailbox password")
parser.add_argument('--ident', required=True, help="Username or local part")
parser.add_argument('--password', required=True, help="New password")
args = parser.parse_args()

try:
    conn = mariadb.connect(
        user="postfix",
        password="secure_password",
        host="localhost",
        database="postfix"
    )
    cursor = conn.cursor()
    phash = bcrypt.hashpw(args.password.encode(), bcrypt.gensalt()).decode()
    query = "UPDATE mailbox SET password=%s WHERE username=%s OR local_part=%s"
    cursor.execute(query, (phash, args.ident, args.ident))
    conn.commit()
except mariadb.Error as e:
    print(f"Database error: {e}")
finally:
    conn.close()
