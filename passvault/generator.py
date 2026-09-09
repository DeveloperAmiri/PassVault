"""Cryptographically secure password generation and strength estimation."""

import math
import secrets
import string

SYMBOLS = "!@#$%^&*()-_=+[]{}<>?~"
AMBIGUOUS = "Il1O0o|`'\""

STRENGTH_LABELS = ["Very weak", "Weak", "Fair", "Strong", "Very strong"]


def generate_password(
    length: int = 20,
    upper: bool = True,
    digits: bool = True,
    symbols: bool = True,
    avoid_ambiguous: bool = False,
) -> str:
    """Generate a random password using the system CSPRNG (``secrets``).

    Guarantees at least one character from every selected character class,
    then fills the rest from the combined pool and shuffles securely.
    """
    length = max(4, min(int(length), 128))

    pools = [string.ascii_lowercase]
    if upper:
        pools.append(string.ascii_uppercase)
    if digits:
        pools.append(string.digits)
    if symbols:
        pools.append(SYMBOLS)

    if avoid_ambiguous:
        pools = ["".join(c for c in pool if c not in AMBIGUOUS) for pool in pools]

    combined = "".join(pools)
    rng = secrets.SystemRandom()

    chars = [secrets.choice(pool) for pool in pools]          # one from each class
    chars += [secrets.choice(combined) for _ in range(length - len(chars))]
    rng.shuffle(chars)
    return "".join(chars)


def password_entropy_bits(password: str) -> float:
    """Estimate search-space entropy in bits based on character classes used."""
    if not password:
        return 0.0
    pool = 0
    if any(c in string.ascii_lowercase for c in password):
        pool += 26
    if any(c in string.ascii_uppercase for c in password):
        pool += 26
    if any(c in string.digits for c in password):
        pool += 10
    if any(c not in string.ascii_letters + string.digits for c in password):
        pool += 32  # rough size of the printable-symbol space
    return len(password) * math.log2(pool) if pool > 1 else 0.0


def strength_label(password: str):
    """Return ``(score 0-4, label, entropy_bits)`` for a password."""
    bits = password_entropy_bits(password)
    if bits < 28:
        score = 0
    elif bits < 36:
        score = 1
    elif bits < 60:
        score = 2
    elif bits < 90:
        score = 3
    else:
        score = 4
    return score, STRENGTH_LABELS[score], bits
