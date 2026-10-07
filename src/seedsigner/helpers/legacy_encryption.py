"""
Legacy Encryption — Python port for SeedSigner (Raspberry Pi Zero)

Implements the Legacy Encryption format exactly as ``legacy-core.js`` (the
JavaScript core embedded in Legacy-offline.html) does, so anything encrypted
here decrypts in the browser and vice versa. Both implementations are checked
against the same published test vectors (``test-vectors.json``).

Format (see PROTOCOL-SPEC.md):

    payload    = base64url(salt(16) || iv(12) || ciphertext)        (no '=')
    password   = canon(benefactor_key) || 0x1F || canon(beneficiary_key)
    key        = PBKDF2-HMAC-SHA256(password, salt, 600000, 32 bytes)
    plaintext  = pad_len(1) || seed || pad_bytes(pad_len)            0..4
    ciphertext = AES-256-GCM(key, iv, plaintext), 16-byte tag appended, no AAD

Every visible byte is random, so a payload carries no marker identifying it as
Legacy. All parameters are fixed by the format.

Dependencies: cryptography
"""

import base64
import hashlib
import hmac
import os
import re
import secrets

from cryptography.exceptions import InvalidTag
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.ciphers.aead import AESGCM
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC

# ---------------------------------------------------------------------------
# BIP-39 English wordlist (2 048 words) — loaded from embit or a file
# ---------------------------------------------------------------------------

_BIP39_WORDLIST: list[str] | None = None


def _load_wordlist() -> list[str]:
    """Load the BIP-39 English wordlist.

    SeedSigner carries it via embit; for local dev / testing fall back to an
    ``english.txt`` (one word per line).
    """
    global _BIP39_WORDLIST
    if _BIP39_WORDLIST is not None:
        return _BIP39_WORDLIST

    try:
        from embit.bip39 import WORDLIST
        _BIP39_WORDLIST = list(WORDLIST)
        return _BIP39_WORDLIST
    except Exception:
        pass

    here = os.path.dirname(__file__)
    search_paths = [
        os.path.join(here, "english.txt"),
        os.path.join(here, "..", "english.txt"),
        os.path.join(here, "..", "seedsigner", "resources", "english.txt"),
        os.path.join(here, "wordlist", "english.txt"),
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
# Format constants
# ---------------------------------------------------------------------------

PBKDF2_ITERATIONS = 600_000
SALT_BYTES = 16
IV_BYTES = 12
TAG_BYTES = 16
KEY_BYTES = 32
MAX_PAD = 4
KEY_SEPARATOR = 0x1F
# Shortest and longest canonical mnemonics: 12 three-letter words (47 bytes)
# and 24 eight-letter words (215 bytes).
MIN_SEED_LEN = 47
MAX_SEED_LEN = 215
MIN_BODY = SALT_BYTES + IV_BYTES + 1 + MIN_SEED_LEN + TAG_BYTES            # 92
MAX_BODY = SALT_BYTES + IV_BYTES + 1 + MAX_SEED_LEN + MAX_PAD + TAG_BYTES  # 264


class LegacyError(ValueError):
    """A user-facing failure. ``code`` matches legacy-core.js:

    BAD_KEY | BAD_SEED | BAD_PAYLOAD | WRONG_KEYS | CORRUPT | VERIFY_FAILED
    """

    def __init__(self, code: str, message: str):
        super().__init__(message)
        self.code = code


# ---------------------------------------------------------------------------
# Key canonicalization (part of the format — must match legacy-core.js)
#
#   1. Curly quotes -> straight quotes; no-break space, tab, CR, LF -> space.
#   2. Collapse runs of spaces to one; strip leading/trailing spaces.
#   3. Require a non-empty result of printable ASCII (0x20-0x7E) only — exactly
#      what the SeedSigner keyboard can type. Anything else is rejected.
# A canonical key never contains 0x1F, so the key separator is unambiguous.
# ---------------------------------------------------------------------------

_KEY_CHAR_MAP = {
    "\u2018": "'",
    "\u2019": "'",
    "\u201c": '"',
    "\u201d": '"',
    "\u00a0": " ",
    "\t": " ",
    "\n": " ",
    "\r": " ",
}


def _describe_char(ch: str) -> str:
    cp = ord(ch)
    hex_ = f"U+{cp:04X}"
    return hex_ if cp < 0x20 or cp == 0x7F else f'"{ch}" ({hex_})'


def canonicalize_key(key: str, label: str = "key") -> str:
    """Return the canonical form of a key, or raise LegacyError(BAD_KEY)."""
    if not isinstance(key, str):
        raise LegacyError("BAD_KEY", f"The {label} is missing.")
    s = "".join(_KEY_CHAR_MAP.get(ch, ch) for ch in key)
    s = re.sub(r" +", " ", s).strip(" ")
    if not s:
        raise LegacyError("BAD_KEY", f"The {label} is empty.")
    for ch in s:
        if not 0x20 <= ord(ch) <= 0x7E:
            raise LegacyError(
                "BAD_KEY",
                f"The {label} contains {_describe_char(ch)}, which is not allowed. "
                "Keys may only use characters on a standard US keyboard: "
                "letters A-Z and a-z, digits, spaces and ordinary punctuation "
                "(no accents, emoji or other alphabets).",
            )
    return s


def _combined_key_bytes(benefactor_key: str, beneficiary_key: str) -> bytes:
    a = canonicalize_key(benefactor_key, "benefactor key")
    b = canonicalize_key(beneficiary_key, "beneficiary key")
    return a.encode("ascii") + bytes([KEY_SEPARATOR]) + b.encode("ascii")


# ---------------------------------------------------------------------------
# Seed phrase handling
# ---------------------------------------------------------------------------

_ASCII_UPPER_TO_LOWER = str.maketrans("ABCDEFGHIJKLMNOPQRSTUVWXYZ", "abcdefghijklmnopqrstuvwxyz")


def normalize_seed_phrase(seed_phrase: str) -> str:
    """Split on ASCII whitespace, ASCII-lowercase, join with single spaces."""
    if not isinstance(seed_phrase, str):
        return ""
    words = [w for w in re.split(r"[ \t\n\r]+", seed_phrase) if w]
    return " ".join(w.translate(_ASCII_UPPER_TO_LOWER) for w in words)


def seed_phrase_error(seed_phrase: str) -> str | None:
    """Validate a 12- or 24-word BIP-39 mnemonic, including the checksum.

    Returns ``None`` when valid, otherwise a short human-readable reason.
    Normalizes first (same rules as legacy-core.js).
    """
    norm = normalize_seed_phrase(seed_phrase)
    words = norm.split(" ") if norm else []
    if len(words) not in (12, 24):
        return f"A seed phrase must be 12 or 24 words (this one has {len(words)})."

    index = {w: i for i, w in enumerate(get_wordlist())}
    bits = ""
    for i, w in enumerate(words):
        idx = index.get(w)
        if idx is None:
            return f'Word {i + 1} ("{w}") is not in the BIP-39 English wordlist.'
        bits += format(idx, "011b")

    checksum_bits = len(bits) // 33         # 4 (12 words) or 8 (24 words)
    entropy_bits = len(bits) - checksum_bits
    entropy = int(bits[:entropy_bits], 2).to_bytes(entropy_bits // 8, "big")
    digest_bits = "".join(format(b, "08b") for b in hashlib.sha256(entropy).digest())
    if digest_bits[:checksum_bits] != bits[entropy_bits:]:
        return ("All words are valid, but the BIP-39 checksum does not match. "
                "Check the word order and the last word.")
    return None


def validate_seed_phrase(seed_phrase: str) -> bool:
    """True iff the phrase is a valid BIP-39 mnemonic (checksum included)."""
    return seed_phrase_error(seed_phrase) is None


# ---------------------------------------------------------------------------
# Encoding and payload parsing (done before any key derivation). Without a
# marker this can only reject what cannot possibly be a Legacy payload (wrong
# alphabet or length); anything else is decided by the GCM tag after PBKDF2.
# ---------------------------------------------------------------------------

_B64URL_RE = re.compile(r"^[A-Za-z0-9_-]+$")


def _b64url_encode(raw: bytes) -> str:
    return base64.urlsafe_b64encode(raw).rstrip(b"=").decode("ascii")


def _b64url_decode(s: str) -> bytes:
    return base64.urlsafe_b64decode(s + "=" * (-len(s) % 4))


def parse_payload(payload: str) -> dict:
    """Validate and split a payload. Raises LegacyError(BAD_PAYLOAD)."""
    if not isinstance(payload, str) or not payload.strip(" \t\n\r"):
        raise LegacyError("BAD_PAYLOAD", "No encrypted seed phrase was provided.")
    s = payload.strip(" \t\n\r")
    if not _B64URL_RE.match(s) or len(s) % 4 == 1:
        raise LegacyError(
            "BAD_PAYLOAD",
            "This is not a Legacy encrypted seed phrase: it contains characters "
            "that never appear in one, or it is incomplete.",
        )
    body = _b64url_decode(s)
    if len(body) < MIN_BODY:
        raise LegacyError(
            "BAD_PAYLOAD",
            "This is too short to be a Legacy encrypted seed phrase. It may have "
            "been cut off; scan it again.",
        )
    if len(body) > MAX_BODY:
        raise LegacyError("BAD_PAYLOAD", "This is too long to be a Legacy encrypted seed phrase.")
    return {
        "salt": body[:SALT_BYTES],
        "iv": body[SALT_BYTES:SALT_BYTES + IV_BYTES],
        "ciphertext": body[SALT_BYTES + IV_BYTES:],
    }


# ---------------------------------------------------------------------------
# Crypto
# ---------------------------------------------------------------------------

def derive_key(password: bytes, salt: bytes) -> bytes:
    """PBKDF2-HMAC-SHA256, 600 000 iterations -> 32-byte AES key."""
    kdf = PBKDF2HMAC(
        algorithm=hashes.SHA256(),
        length=KEY_BYTES,
        salt=salt,
        iterations=PBKDF2_ITERATIONS,
    )
    return kdf.derive(password)


def _open_with_key(key: bytes, parsed: dict) -> bytes:
    try:
        plain = AESGCM(key).decrypt(parsed["iv"], parsed["ciphertext"], None)
    except InvalidTag:
        raise LegacyError(
            "WRONG_KEYS",
            "Decryption failed. Either a key is wrong (spelling, capitalization, "
            "punctuation and order all matter: benefactor key first, beneficiary "
            "key second), or this is not a Legacy QR, or it is damaged.",
        ) from None
    pad_len = plain[0]
    if pad_len > MAX_PAD or len(plain) < 1 + pad_len:
        raise LegacyError("CORRUPT", "Decryption succeeded, but the padding is invalid.")
    return plain[1:len(plain) - pad_len]


def encrypt_with_params(
    seed_phrase: str,
    benefactor_key: str,
    beneficiary_key: str,
    *,
    salt: bytes,
    iv: bytes,
    pad_bytes: bytes,
) -> str:
    """Deterministic encryption for published test vectors.

    Real use goes through encrypt_seed_phrase(), which draws salt, iv and
    padding from the OS CSPRNG.
    """
    password = _combined_key_bytes(benefactor_key, beneficiary_key)
    seed = normalize_seed_phrase(seed_phrase)
    err = seed_phrase_error(seed)
    if err is not None:
        raise LegacyError("BAD_SEED", err)

    if len(salt) != SALT_BYTES:
        raise ValueError("salt must be 16 bytes")
    if len(iv) != IV_BYTES:
        raise ValueError("iv must be 12 bytes")
    if len(pad_bytes) > MAX_PAD:
        raise ValueError("pad_bytes must be 0-4 bytes")

    seed_bytes = seed.encode("ascii")
    key = derive_key(password, salt)
    plaintext = bytes([len(pad_bytes)]) + seed_bytes + pad_bytes
    ciphertext = AESGCM(key).encrypt(iv, plaintext, None)
    payload = _b64url_encode(salt + iv + ciphertext)

    # Read the payload back through the same strict parser a decryptor uses and
    # open it with the same key. Never hand out a payload that isn't proven to
    # decrypt to exactly this seed.
    try:
        check = _open_with_key(key, parse_payload(payload))
    except LegacyError:
        raise LegacyError(
            "VERIFY_FAILED",
            "Self-check failed: the new QR did not decrypt. Nothing was produced; try again.",
        ) from None
    if not hmac.compare_digest(check, seed_bytes):
        raise LegacyError(
            "VERIFY_FAILED",
            "Self-check failed: the new QR decrypted to the wrong data. Nothing was "
            "produced; try again.",
        )
    return payload


def encrypt_seed_phrase(seed_phrase: str, benefactor_key: str, beneficiary_key: str) -> str:
    """Encrypt a seed phrase with the dual-key scheme.

    Validates the mnemonic (including checksum) and both keys, and self-checks
    the result before returning it. Decryption requires both keys, in order.
    """
    return encrypt_with_params(
        seed_phrase,
        benefactor_key,
        beneficiary_key,
        salt=os.urandom(SALT_BYTES),
        iv=os.urandom(IV_BYTES),
        pad_bytes=os.urandom(secrets.randbelow(MAX_PAD + 1)),
    )


def decrypt_seed_phrase(encrypted_seed_phrase: str, benefactor_key: str, beneficiary_key: str) -> str:
    """Decrypt a payload back to the seed phrase.

    The result must be a valid canonical mnemonic.
    """
    parsed = parse_payload(encrypted_seed_phrase)
    password = _combined_key_bytes(benefactor_key, beneficiary_key)
    key = derive_key(password, parsed["salt"])
    plain = _open_with_key(key, parsed)
    try:
        seed = plain.decode("utf-8")
    except UnicodeDecodeError:
        raise LegacyError("CORRUPT", "Decryption succeeded, but the result is not text.") from None
    if seed != normalize_seed_phrase(seed) or seed_phrase_error(seed) is not None:
        raise LegacyError(
            "CORRUPT", "Decryption succeeded, but the result is not a valid BIP-39 seed phrase."
        )
    return seed


# ---------------------------------------------------------------------------
# QR helpers for SeedSigner I/O
# ---------------------------------------------------------------------------

def encrypted_to_qr_data(encrypted: str) -> str:
    """Return the string to encode into a QR code (the payload itself)."""
    return encrypted


def qr_data_to_encrypted(qr_text: str) -> str:
    """Parse a scanned QR string back into the encrypted payload."""
    return qr_text.strip()


# ---------------------------------------------------------------------------
# CLI smoke test
# ---------------------------------------------------------------------------

if __name__ == "__main__":
    import time

    # Canonical all-zero-entropy mnemonic (checksum word = "about").
    seed = "abandon " * 11 + "about"
    bk = "benefactor-password-123"
    byk = "beneficiary-password-456"

    t0 = time.time()
    encrypted = encrypt_seed_phrase(seed, bk, byk)
    print(f"Encrypted   : {encrypted[:60]}...  ({time.time() - t0:.2f}s)")

    t0 = time.time()
    decrypted = decrypt_seed_phrase(encrypted, bk, byk)
    print(f"Decrypted   : {decrypted}  ({time.time() - t0:.2f}s)")

    assert decrypted == seed, "Round-trip FAILED"
    print("Round-trip OK")
