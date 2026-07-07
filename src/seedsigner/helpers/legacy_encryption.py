"""
Legacy Encryption — Python port for SeedSigner (Raspberry Pi Zero)

Implements the same AES-256-GCM + PBKDF2 dual-key encryption scheme as
Legacy-offline.html, producing byte-identical ciphertext format so that
anything encrypted here can be decrypted in the browser and vice versa.

Dependencies: cryptography (pure-Python fallback works on Pi Zero)
Install:      pip install cryptography
"""

import os
import re
import base64
import hashlib
import secrets
from cryptography.hazmat.primitives.ciphers.aead import AESGCM
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
from cryptography.hazmat.primitives import hashes

# ---------------------------------------------------------------------------
# BIP-39 English wordlist (2 048 words) — loaded from file or embedded
# ---------------------------------------------------------------------------

_BIP39_WORDLIST: list[str] | None = None


def _load_wordlist() -> list[str]:
    """Load the BIP-39 English wordlist.

    Tries to read from a bundled `english.txt` (one word per line) first,
    then falls back to an embedded tuple.  SeedSigner already ships this
    file so we just reuse it.
    """
    global _BIP39_WORDLIST
    if _BIP39_WORDLIST is not None:
        return _BIP39_WORDLIST

    # Try embit first — that's how SeedSigner itself carries the wordlist
    try:
        from embit.bip39 import WORDLIST
        _BIP39_WORDLIST = list(WORDLIST)
        return _BIP39_WORDLIST
    except Exception:
        pass

    # Fall back to english.txt file (useful for local dev / testing)
    search_paths = [
        os.path.join(os.path.dirname(__file__), "english.txt"),
        os.path.join(os.path.dirname(__file__), "..", "seedsigner", "resources", "english.txt"),
        os.path.join(os.path.dirname(__file__), "wordlist", "english.txt"),
    ]
    for path in search_paths:
        try:
            with open(path, "r") as f:
                words = [line.strip() for line in f if line.strip()]
            if len(words) == 2048:
                _BIP39_WORDLIST = words
                return _BIP39_WORDLIST
        except FileNotFoundError:
            continue

    raise FileNotFoundError(
        "BIP-39 wordlist not found. Ensure embit is installed or place english.txt "
        "next to this module."
    )


def get_wordlist() -> list[str]:
    return _load_wordlist()


# ---------------------------------------------------------------------------
# Core cryptographic functions
# ---------------------------------------------------------------------------

PBKDF2_ITERATIONS = 600_000
SALT_BYTES = 16
IV_BYTES = 12
KEY_BITS = 256
KEY_BYTES = KEY_BITS // 8


def derive_key(password: str, salt: bytes, iterations: int = PBKDF2_ITERATIONS) -> bytes:
    """PBKDF2-SHA256 key derivation — mirrors deriveKey() in the JS.

    ``iterations`` defaults to the canonical 600 000 but is a parameter so the
    v2 envelope can carry (and a future build can bump) the count.
    """
    kdf = PBKDF2HMAC(
        algorithm=hashes.SHA256(),
        length=KEY_BYTES,
        salt=salt,
        iterations=iterations,
    )
    return kdf.derive(password.encode("utf-8"))


def encrypt_data(plaintext: str, password: str) -> dict:
    """Encrypt a plaintext string with AES-256-GCM.

    Returns a dict with base64-encoded salt, iv, ciphertext, and the
    integer paddingLength — the same structure as the JS encryptData().
    """
    # Random salt and IV
    salt = os.urandom(SALT_BYTES)
    iv = os.urandom(IV_BYTES)

    # Random padding (0–4 bytes) appended to plaintext before encoding
    padding_length = secrets.randbelow(5)  # 0..4
    padded = plaintext
    for _ in range(padding_length):
        padded += chr(secrets.randbelow(256))

    # Derive key and encrypt
    key = derive_key(password, salt)
    aesgcm = AESGCM(key)
    # AES-GCM ciphertext includes the 16-byte auth tag appended by default
    ciphertext = aesgcm.encrypt(iv, padded.encode("utf-8"), None)

    # Encode to base64 (standard, with padding) — matches btoa() in browser
    salt_b64 = base64.b64encode(salt).decode("ascii")
    iv_b64 = base64.b64encode(iv).decode("ascii")
    ct_b64 = base64.b64encode(ciphertext).decode("ascii")

    return {
        "salt": salt_b64,
        "iv": iv_b64,
        "ciphertext": ct_b64,
        "paddingLength": padding_length,
    }


def decrypt_data(data: dict, password: str) -> str:
    """Decrypt a dict produced by encrypt_data (or the JS equivalent)."""
    salt = base64.b64decode(data["salt"])
    iv = base64.b64decode(data["iv"])
    ciphertext = base64.b64decode(data["ciphertext"])
    padding_length = int(data["paddingLength"])

    key = derive_key(password, salt)
    aesgcm = AESGCM(key)

    decrypted_bytes = aesgcm.decrypt(iv, ciphertext, None)
    decrypted_text = decrypted_bytes.decode("utf-8", errors="replace")

    # Strip random padding
    if 0 < padding_length <= len(decrypted_text):
        decrypted_text = decrypted_text[:-padding_length]

    return decrypted_text


# ---------------------------------------------------------------------------
# Seed-phrase–level functions (dual-key wrapper)
# ---------------------------------------------------------------------------

def seed_phrase_error(seed_phrase: str) -> str | None:
    """Validate a BIP-39 mnemonic, including the checksum.

    Returns ``None`` when the phrase is fully valid, otherwise a short
    human-readable reason — so the UI can show an *accurate* message instead
    of always claiming "Bad Checksum".
    """
    words = seed_phrase.split(" ")
    if len(words) not in (12, 24):
        return "Seed phrase must be 12 or 24 words."

    wordlist = get_wordlist()
    indices: list[int] = []
    for w in words:
        try:
            indices.append(wordlist.index(w))
        except ValueError:
            return "Contains a word that isn't in the BIP-39 list."

    # Concatenate the 11-bit word indices, then split into entropy + checksum.
    bits = "".join(format(i, "011b") for i in indices)
    total_bits = len(words) * 11           # 132 (12 words) or 264 (24 words)
    checksum_bits = total_bits // 33       # 4 or 8  (CS = ENT/32)
    entropy_bits = total_bits - checksum_bits
    entropy = int(bits[:entropy_bits], 2).to_bytes(entropy_bits // 8, "big")
    digest_bits = "".join(format(b, "08b") for b in hashlib.sha256(entropy).digest())
    if digest_bits[:checksum_bits] != bits[entropy_bits:]:
        return "The last word doesn't match the BIP-39 checksum."

    return None


def validate_seed_phrase(seed_phrase: str) -> bool:
    """True iff the phrase is a valid BIP-39 mnemonic (checksum included)."""
    return seed_phrase_error(seed_phrase) is None


# ---------------------------------------------------------------------------
# Protocol v2 envelope (see PROTOCOL-V2-SPEC.md)
#   "LE2." + base64url( header(35) || ciphertext )
#   header = version(1) kdf_id(1) iterations(4,BE) padLen(1) salt(16) iv(12)
# ---------------------------------------------------------------------------

V2_PREFIX = "LE2."
V2_VERSION = 0x02
KDF_PBKDF2_SHA256 = 0x01
V2_HEADER_LEN = 35
# Bounds on the header's iteration count. The header is only authenticated
# AFTER key derivation, so without a cap a forged payload could set
# iterations=0xFFFFFFFF and stall the device for days before the GCM tag
# ever gets checked.
MIN_PBKDF2_ITERATIONS = 100_000
MAX_PBKDF2_ITERATIONS = 10_000_000
# Unit Separator (0x1F) — untypeable, so the benefactor/beneficiary boundary is
# unambiguous: "ab"+"c" no longer derives the same key as "a"+"bc".
KEY_SEPARATOR = "\x1f"


def _b64url_encode(raw: bytes) -> str:
    return base64.urlsafe_b64encode(raw).rstrip(b"=").decode("ascii")


def _b64url_decode(s: str) -> bytes:
    return base64.urlsafe_b64decode(s + "=" * (-len(s) % 4))


def _combined_key_v2(benefactor_key: str, beneficiary_key: str) -> str:
    return benefactor_key + KEY_SEPARATOR + beneficiary_key


def encrypt_seed_phrase(
    seed_phrase: str,
    benefactor_key: str,
    beneficiary_key: str,
) -> str:
    """Encrypt a BIP-39 seed phrase with the dual-key scheme (Protocol v2).

    Returns an ``LE2.`` payload that Legacy-offline.html's decryptSeedPhrase()
    can read. Decryption requires both keys in the same order.
    """
    err = seed_phrase_error(seed_phrase)
    if err is not None:
        raise ValueError(err)

    salt = os.urandom(SALT_BYTES)
    iv = os.urandom(IV_BYTES)
    pad_len = secrets.randbelow(5)  # 0..4
    iterations = PBKDF2_ITERATIONS

    header = (
        bytes([V2_VERSION, KDF_PBKDF2_SHA256])
        + iterations.to_bytes(4, "big")
        + bytes([pad_len])
        + salt
        + iv
    )
    assert len(header) == V2_HEADER_LEN

    # Pad on the BYTE array (not the string) so high bytes can't desync padLen.
    plaintext = seed_phrase.encode("utf-8") + bytes(
        secrets.randbelow(256) for _ in range(pad_len)
    )

    key = derive_key(_combined_key_v2(benefactor_key, beneficiary_key), salt, iterations)
    # Header is bound as GCM AAD, so tampering with version/params fails the tag.
    ciphertext = AESGCM(key).encrypt(iv, plaintext, header)

    return V2_PREFIX + _b64url_encode(header + ciphertext)


def decrypt_seed_phrase(
    encrypted_seed_phrase: str,
    benefactor_key: str,
    beneficiary_key: str,
) -> str:
    """Decrypt a Legacy payload. Dispatches on version: ``LE2.`` -> v2,
    no marker -> legacy v1 (kept forever for backward compatibility).
    """
    payload = encrypted_seed_phrase.strip()
    m = re.match(r"^LE(\d+)\.", payload)
    if m:
        body = _b64url_decode(payload[len(m.group(0)):])
        version = body[0] if body else None
        if version == V2_VERSION:
            return _decrypt_v2(body, benefactor_key, beneficiary_key)
        raise ValueError(f"Unsupported Legacy Encryption version: {version!r}")
    return _decrypt_v1(payload, benefactor_key, beneficiary_key)


def _decrypt_v2(body: bytes, benefactor_key: str, beneficiary_key: str) -> str:
    if len(body) < V2_HEADER_LEN:
        raise ValueError("Truncated v2 payload.")
    kdf_id = body[1]
    if kdf_id != KDF_PBKDF2_SHA256:
        raise ValueError(f"Unsupported KDF id: 0x{kdf_id:02x}")
    iterations = int.from_bytes(body[2:6], "big")
    if not (MIN_PBKDF2_ITERATIONS <= iterations <= MAX_PBKDF2_ITERATIONS):
        raise ValueError(f"Unreasonable PBKDF2 iteration count: {iterations}")
    pad_len = body[6]
    salt = body[7:23]
    iv = body[23:35]
    header = body[:V2_HEADER_LEN]
    ciphertext = body[V2_HEADER_LEN:]

    key = derive_key(_combined_key_v2(benefactor_key, beneficiary_key), salt, iterations)
    plaintext = AESGCM(key).decrypt(iv, ciphertext, header)
    if pad_len:
        plaintext = plaintext[:-pad_len]
    return plaintext.decode("utf-8")


def _decrypt_v1(payload: str, benefactor_key: str, beneficiary_key: str) -> str:
    # v1: keys concatenated with NO separator (the historical format).
    combined_key = benefactor_key + beneficiary_key
    decoded = base64.b64decode(payload + "=" * (-len(payload) % 4)).decode("utf-8")
    parts = decoded.split(".")
    if len(parts) != 4:
        raise ValueError("Invalid encrypted seed phrase format.")
    data = {
        "salt": parts[0],
        "iv": parts[1],
        "ciphertext": parts[2],
        "paddingLength": int(parts[3]),
    }
    return decrypt_data(data, combined_key)


# ---------------------------------------------------------------------------
# QR helpers for SeedSigner I/O
# ---------------------------------------------------------------------------

def encrypted_to_qr_data(encrypted: str) -> str:
    """Return the string that should be encoded into a QR code.

    For now this is just the raw base64 blob — compact enough for a
    Version-10 QR at medium ECC (~211 alphanumeric chars).
    """
    return encrypted


def qr_data_to_encrypted(qr_text: str) -> str:
    """Parse a scanned QR string back into the encrypted payload."""
    return qr_text.strip()


# ---------------------------------------------------------------------------
# CLI smoke test
# ---------------------------------------------------------------------------

if __name__ == "__main__":
    import time

    # Use a tiny test wordlist for the CLI demo
    _BIP39_WORDLIST = [
        "abandon", "ability", "able", "about", "above", "absent", "absorb",
        "abstract", "absurd", "abuse", "access", "accident",
    ]

    # Canonical all-zero-entropy mnemonic (checksum word = "about") — valid BIP-39.
    seed = "abandon " * 11 + "about"
    bk = "benefactor-password-123"
    byk = "beneficiary-password-456"

    print(f"Seed phrase : {seed}")
    print(f"Benefactor  : {bk}")
    print(f"Beneficiary : {byk}")
    print()

    t0 = time.time()
    encrypted = encrypt_seed_phrase(seed, bk, byk)
    t1 = time.time()
    print(f"Encrypted   : {encrypted[:60]}...")
    print(f"Encrypt time: {t1 - t0:.2f}s")
    print()

    t0 = time.time()
    decrypted = decrypt_seed_phrase(encrypted, bk, byk)
    t1 = time.time()
    print(f"Decrypted   : {decrypted}")
    print(f"Decrypt time: {t1 - t0:.2f}s")
    print()

    assert decrypted == seed, "Round-trip FAILED"
    print("Round-trip OK")
