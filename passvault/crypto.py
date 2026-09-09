"""Key derivation and Fernet (AES-128-CBC + HMAC) encryption helpers.

Security model
--------------
* A random 16-byte salt is generated once and stored next to the database.
* The master password is stretched with PBKDF2-HMAC-SHA256 (600,000 rounds)
  to produce a 256-bit key, wrapped into a Fernet key.
* Every stored secret is encrypted with Fernet (AES-128-CBC + HMAC-SHA256),
  which provides authenticated encryption: tampered ciphertext is rejected.
* A "verifier" ciphertext is stored in the DB so we can tell whether the
  entered master password is correct without ever storing the password.
"""

import base64
import os
from pathlib import Path

from cryptography.fernet import Fernet, InvalidToken
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC

PBKDF2_ITERATIONS = 600_000
_SALT_SIZE = 16

#: Plain-text that is encrypted and stored as the master-password verifier.
VERIFIER_PLAINTEXT = "passvault::verifier::ok"


def _derive_key(master_password: str, salt: bytes) -> bytes:
    """Stretch *master_password* into a Fernet key using PBKDF2."""
    kdf = PBKDF2HMAC(
        algorithm=hashes.SHA256(),
        length=32,
        salt=salt,
        iterations=PBKDF2_ITERATIONS,
    )
    return base64.urlsafe_b64encode(kdf.derive(master_password.encode("utf-8")))


class VaultCrypto:
    """Derives Fernet keys from the master password and encrypts/decrypts text."""

    def __init__(self, data_dir):
        self.data_dir = Path(data_dir)
        self.data_dir.mkdir(parents=True, exist_ok=True)
        self.salt_path = self.data_dir / "vault.salt"

    def load_or_create_salt(self) -> bytes:
        """Return the existing salt, or create one on first use."""
        if self.salt_path.exists():
            return self.salt_path.read_bytes()
        salt = os.urandom(_SALT_SIZE)
        self.salt_path.write_bytes(salt)
        try:  # best-effort permission tightening (POSIX only)
            os.chmod(self.salt_path, 0o600)
        except OSError:
            pass
        return salt

    def fernet_for(self, master_password: str) -> Fernet:
        """Build a Fernet instance for the given master password."""
        return Fernet(_derive_key(master_password, self.load_or_create_salt()))

    @staticmethod
    def encrypt(fernet: Fernet, value: str) -> str:
        """Encrypt a UTF-8 string, returning an ASCII-safe token."""
        return fernet.encrypt(value.encode("utf-8")).decode("ascii")

    @staticmethod
    def decrypt(fernet: Fernet, token: str) -> str:
        """Decrypt a token; raises ValueError on wrong password or tampering."""
        try:
            return fernet.decrypt(token.encode("ascii")).decode("utf-8")
        except InvalidToken:
            raise ValueError(
                "Wrong master password for this vault (or the data was tampered with)."
            )
