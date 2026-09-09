"""Unit tests for PassVault (run with: pytest)."""

import shutil
import sys
from pathlib import Path

import pytest
from cryptography.fernet import Fernet

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

from passvault.crypto import VaultCrypto, VERIFIER_PLAINTEXT, PBKDF2_ITERATIONS  # noqa: E402
from passvault.db import VaultDB  # noqa: E402
from passvault.generator import generate_password, strength_label  # noqa: E402


@pytest.fixture()
def tmp_vault(tmp_path):
    return VaultCrypto(tmp_path)


def test_encrypt_decrypt_roundtrip(tmp_vault):
    fernet = tmp_vault.fernet_for("correct horse battery staple")
    token = VaultCrypto.encrypt(fernet, "s3cret-Pass!")
    assert VaultCrypto.decrypt(fernet, token) == "s3cret-Pass!"


def test_wrong_password_rejected(tmp_vault):
    f1 = tmp_vault.fernet_for("master-one")
    token = VaultCrypto.encrypt(f1, "data")
    f2 = tmp_vault.fernet_for("master-two")
    with pytest.raises(ValueError):
        VaultCrypto.decrypt(f2, token)


def test_tampered_ciphertext_rejected(tmp_vault):
    fernet = tmp_vault.fernet_for("master")
    token = VaultCrypto.encrypt(fernet, "data")
    with pytest.raises(ValueError):
        VaultCrypto.decrypt(fernet, token[:-4] + "AAAA")


def test_salt_is_stable_across_unlocks(tmp_vault):
    tmp_vault.fernet_for("master")
    salt1 = tmp_vault.salt_path.read_bytes()
    tmp_vault.fernet_for("master")
    assert tmp_vault.salt_path.read_bytes() == salt1


def test_pbkdf2_uses_hard_iterations():
    assert PBKDF2_ITERATIONS >= 600_000


def test_verifier_flow(tmp_vault, tmp_path):
    fernet = tmp_vault.fernet_for("master-password-123")
    db = VaultDB(tmp_path / "vault.db")
    db.set_meta("verifier", VaultCrypto.encrypt(fernet, VERIFIER_PLAINTEXT))
    assert VaultCrypto.decrypt(fernet, db.get_meta("verifier")) == VERIFIER_PLAINTEXT
    db.close()


def test_db_crud(tmp_path):
    db = VaultDB(tmp_path / "vault.db")
    entry_id = db.add_entry("github", "octocat", "https://github.com", "enc-token", "work")
    assert entry_id == 1
    entries = db.list_entries()
    assert len(entries) == 1 and entries[0]["name"] == "github"

    found = db.find_by_name("GitHub")  # case-insensitive
    assert len(found) == 1 and found[0]["username"] == "octocat"

    assert db.delete_entry(entry_id) is True
    assert db.list_entries() == []
    assert db.delete_entry(999) is False
    db.close()


def test_generated_password_shape():
    pw = generate_password(length=24)
    assert len(pw) == 24
    assert any(c.isupper() for c in pw)
    assert any(c.isdigit() for c in pw)
    assert any(not c.isalnum() for c in pw)


def test_generated_passwords_are_unique():
    pws = {generate_password(length=32) for _ in range(20)}
    assert len(pws) == 20  # collisions would be extraordinary


def test_strength_scoring():
    assert strength_label("1234")[1] == "Very weak"
    assert strength_label("CorrectHorse-Battery!Staple#2026")[1] in ("Strong", "Very strong")
