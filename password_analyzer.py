"""
Advanced Password Strength Analyzer
Domain: Cyber Security
Language: Python
Database: SQLite (built into Python)

Features:
- Password length and complexity checks
- Common-password/pattern detection
- Strong password suggestions
- Password history / reuse checking
- Stores salted PBKDF2-HMAC-SHA256 hashes, never plaintext passwords

IMPORTANT:
This is an educational internship project, not a production authentication system.
Do not enter or store your real account passwords while testing.
"""

import hashlib
import hmac
import re
import secrets
import sqlite3
import string
from getpass import getpass
from pathlib import Path

DB_FILE = Path(__file__).with_name("password_history.db")
PBKDF2_ITERATIONS = 600_000
MIN_LENGTH = 12

COMMON_PATTERNS = (
    "password", "12345", "123456", "qwerty",
    "letmein", "admin", "welcome", "abc123"
)


def create_database():
    """Create the password history table if it does not already exist."""
    with sqlite3.connect(DB_FILE) as connection:
        connection.execute("""
            CREATE TABLE IF NOT EXISTS password_history (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                username TEXT NOT NULL,
                salt BLOB NOT NULL,
                password_hash BLOB NOT NULL,
                created_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP
            )
        """)
        connection.execute("""
            CREATE INDEX IF NOT EXISTS idx_password_history_username
            ON password_history(username)
        """)


def hash_password(password, salt=None):
    """Return a salted PBKDF2 hash. The original password is not stored."""
    if salt is None:
        salt = secrets.token_bytes(16)

    password_hash = hashlib.pbkdf2_hmac(
        "sha256",
        password.encode("utf-8"),
        salt,
        PBKDF2_ITERATIONS
    )
    return salt, password_hash


def password_was_used(username, password):
    """Check whether this password matches any saved hash for this username."""
    with sqlite3.connect(DB_FILE) as connection:
        rows = connection.execute(
            "SELECT salt, password_hash FROM password_history WHERE username = ?",
            (username,)
        ).fetchall()

    for salt, saved_hash in rows:
        _, candidate_hash = hash_password(password, salt)
        if hmac.compare_digest(candidate_hash, saved_hash):
            return True
    return False


def save_password_hash(username, password):
    """Save only a new salted hash, never the plaintext password."""
    salt, password_hash = hash_password(password)
    with sqlite3.connect(DB_FILE) as connection:
        connection.execute(
            "INSERT INTO password_history (username, salt, password_hash) VALUES (?, ?, ?)",
            (username, salt, password_hash)
        )


def analyze_password(password):
    """Return a score, strength label, and improvement suggestions."""
    score = 0
    suggestions = []

    if len(password) >= MIN_LENGTH:
        score += 1
    else:
        suggestions.append(f"Use at least {MIN_LENGTH} characters.")

    if re.search(r"[a-z]", password):
        score += 1
    else:
        suggestions.append("Add at least one lowercase letter.")

    if re.search(r"[A-Z]", password):
        score += 1
    else:
        suggestions.append("Add at least one uppercase letter.")

    if re.search(r"\d", password):
        score += 1
    else:
        suggestions.append("Add at least one number.")

    if re.search(r"[^A-Za-z0-9]", password):
        score += 1
    else:
        suggestions.append("Add at least one special character.")

    lowered = password.lower()
    common_found = any(pattern in lowered for pattern in COMMON_PATTERNS)

    if common_found:
        score = max(0, score - 2)
        suggestions.append("Avoid common words, keyboard patterns, and number sequences.")

    if len(set(password)) <= 2 and len(password) >= 8:
        score = max(0, score - 1)
        suggestions.append("Avoid repeating the same one or two characters.")

    if len(password) < 8 or common_found or score <= 2:
        strength = "Weak"
    elif score == 3:
        strength = "Moderate"
    elif score == 4:
        strength = "Strong"
    else:
        strength = "Very Strong"

    return score, strength, suggestions, common_found


def generate_password(length=16):
    """Generate a random password containing each required character type."""
    if length < 12:
        length = 12

    groups = [
        string.ascii_lowercase,
        string.ascii_uppercase,
        string.digits,
        "!@#$%^&*()-_=+?"
    ]

    # Guarantee at least one character from each group.
    characters = [secrets.choice(group) for group in groups]
    all_characters = "".join(groups)
    characters.extend(secrets.choice(all_characters) for _ in range(length - len(characters)))
    secrets.SystemRandom().shuffle(characters)
    return "".join(characters)


def main():
    create_database()

    print("\n======================================")
    print("   ADVANCED PASSWORD STRENGTH ANALYZER")
    print("             CYBER SECURITY")
    print("======================================")
    print("Educational project: do not enter your real account password.\n")

    username = input("Enter a test username: ").strip()
    if not username:
        print("Username cannot be empty.")
        return

    password = getpass("Enter a test password (input hidden): ")
    if not password:
        print("Password cannot be empty.")
        return

    score, strength, suggestions, common_found = analyze_password(password)
    reused = password_was_used(username, password)

    print("\n----------- ANALYSIS RESULT -----------")
    print(f"Strength          : {strength}")
    print(f"Criteria score    : {score}/5")
    print(f"Password length   : {len(password)} characters")
    print(f"Common pattern    : {'Yes' if common_found else 'Not detected'}")
    print(f"Previously used   : {'Yes' if reused else 'No'}")

    if reused:
        print("Warning: Choose a password that has not been used before.")
    if suggestions:
        print("\nSuggestions:")
        for item in suggestions:
            print(f"- {item}")
    else:
        print("\nAll basic complexity checks passed.")

    if not reused:
        choice = input("\nSave this password in local history as a salted hash? (y/n): ").strip().lower()
        if choice == "y":
            save_password_hash(username, password)
            print("Password history saved. Plaintext password was not stored.")
        else:
            print("Password was not saved.")

    print("\nSuggested random password (example):")
    print(generate_password())
    print("---------------------------------------")
    print("Database file:", DB_FILE.name)
    print("Never share your passwords or database file.")


if __name__ == "__main__":
    main()
