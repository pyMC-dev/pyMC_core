"""
Modem-based Identity for MeshCore KISS Modem

Provides an Identity implementation that delegates cryptographic operations
to the KISS modem hardware, keeping the private key secure on the device.
"""

from typing import TYPE_CHECKING

from nacl.public import PublicKey
from nacl.signing import VerifyKey

from . import CryptoUtils

if TYPE_CHECKING:
    from pymc_core.hardware.kiss_modem_wrapper import KissModemWrapper


class ModemIdentity:
    """
    Identity implementation using the KISS modem's cryptographic capabilities.

    Delegates signing, verification, and key exchange to the modem hardware,
    ensuring the private key never leaves the secure modem environment.

    Implements the same interface as LocalIdentity for compatibility with
    the rest of the pyMC_core stack.
    """

    def __init__(self, modem: "KissModemWrapper"):
        """
        Initialize ModemIdentity with a connected KISS modem.

        Args:
            modem: A connected KissModemWrapper instance

        Raises:
            ValueError: If modem is not connected or identity cannot be retrieved
        """
        if not modem.is_connected:
            raise ValueError("Modem must be connected before creating ModemIdentity")

        self._modem = modem

        # Get the modem's public key
        pubkey = modem.get_identity()
        if pubkey is None or len(pubkey) != 32:
            raise ValueError("Failed to retrieve modem identity")

        self._ed25519_pubkey = pubkey
        self.verify_key = VerifyKey(pubkey)

        # Derive X25519 public key for ECDH
        x25519_pubkey = CryptoUtils.ed25519_pk_to_x25519(pubkey)
        self.x25519_pubkey = PublicKey(x25519_pubkey)

        # Cache the X25519 public key bytes
        self._x25519_public = x25519_pubkey

    def get_public_key(self) -> bytes:
        """
        Get the Ed25519 public key for this identity.

        Returns:
            The 32-byte Ed25519 public key.
        """
        return self._ed25519_pubkey

    def get_address_bytes(self) -> bytes:
        """
        Get the address bytes derived from the public key.

        Returns:
            The first byte of SHA256 hash of the public key, used as address.
        """
        return CryptoUtils.sha256(self._ed25519_pubkey)[:1]

    def get_shared_public_key(self) -> bytes:
        """
        Get the X25519 public key for ECDH operations.

        Returns:
            The 32-byte X25519 public key.
        """
        return self._x25519_public

    def sign(self, message: bytes) -> bytes:
        """
        Sign a message using the modem's private key.

        Args:
            message: The message to sign.

        Returns:
            The 64-byte Ed25519 signature.

        Raises:
            RuntimeError: If signing fails
        """
        signature = self._modem.sign_data(message)
        if signature is None:
            raise RuntimeError("Modem signing failed")
        return signature

    def verify(self, message: bytes, signature: bytes) -> bool:
        """
        Verify a signature against a message.

        Note: This uses PyNaCl locally since verification only needs
        the public key and is not security-sensitive.

        Args:
            message: The original message bytes.
            signature: The signature to verify.

        Returns:
            True if the signature is valid, False otherwise.
        """
        result = self._modem.verify_signature(self._ed25519_pubkey, signature, message)
        if result is None:
            # Fall back to local verification if modem fails
            try:
                self.verify_key.verify(message, signature)
                return True
            except Exception:
                return False
        return result

    def calc_shared_secret(self, remote_ed25519_pubkey: bytes) -> bytes:
        """
        Compute the ECDH shared secret with a remote party's public key.

        Uses the modem's key_exchange command for secure computation.
        The modem internally converts the Ed25519 public key to X25519
        and performs the ECDH computation.

        Note: This method signature differs from Identity.calc_shared_secret()
        which takes a local private key. ModemIdentity.calc_shared_secret()
        takes the remote's Ed25519 public key because the modem holds the
        local private key internally.

        For use in pyMC_core handlers, which call calc_shared_secret on the
        *peer's* Identity object (not on LocalIdentity/ModemIdentity), this
        method is provided for cases where you want to compute a shared
        secret directly using the modem's identity.

        Args:
            remote_ed25519_pubkey: The remote party's 32-byte Ed25519 public key.
                                  The modem converts this to X25519 internally.

        Returns:
            The 32-byte shared secret for encryption.

        Raises:
            RuntimeError: If key exchange fails
        """
        if len(remote_ed25519_pubkey) != 32:
            raise ValueError("Remote public key must be 32 bytes (Ed25519)")

        shared_secret = self._modem.key_exchange(remote_ed25519_pubkey)
        if shared_secret is None:
            raise RuntimeError("Modem key exchange failed")
        return shared_secret

    def get_private_key(self) -> bytes:
        """
        Get the X25519 private key for ECDH operations.

        Note: ModemIdentity does NOT expose the private key since it
        remains secure on the modem. This method raises an error.

        Raises:
            RuntimeError: Always, as private key is not accessible
        """
        raise RuntimeError(
            "ModemIdentity does not expose private keys. "
            "Use calc_shared_secret() for ECDH operations."
        )

    def get_signing_key_bytes(self) -> bytes:
        """
        Get the signing key bytes for this identity.

        Note: ModemIdentity does NOT expose the signing key since it
        remains secure on the modem. This method raises an error.

        Raises:
            RuntimeError: Always, as signing key is not accessible
        """
        raise RuntimeError(
            "ModemIdentity does not expose signing keys. " "Use sign() for signing operations."
        )

    # Additional modem-specific methods

    def hash_data(self, data: bytes) -> bytes:
        """
        Compute SHA-256 hash using the modem.

        Args:
            data: Data to hash.

        Returns:
            The 32-byte SHA-256 hash.

        Raises:
            RuntimeError: If hashing fails
        """
        result = self._modem.hash_data(data)
        if result is None:
            # Fall back to local hashing
            return CryptoUtils.sha256(data)
        return result

    def get_random(self, length: int) -> bytes:
        """
        Get random bytes from the modem's hardware RNG.

        Args:
            length: Number of random bytes (1-64).

        Returns:
            Random bytes from the modem.

        Raises:
            RuntimeError: If random generation fails
        """
        result = self._modem.get_random(length)
        if result is None:
            raise RuntimeError("Modem random generation failed")
        return result

    def encrypt(self, key: bytes, plaintext: bytes) -> tuple[bytes, bytes]:
        """
        Encrypt data using the modem.

        Args:
            key: 32-byte encryption key.
            plaintext: Data to encrypt.

        Returns:
            Tuple of (2-byte MAC, ciphertext).

        Raises:
            RuntimeError: If encryption fails
        """
        result = self._modem.encrypt_data(key, plaintext)
        if result is None:
            raise RuntimeError("Modem encryption failed")
        return result

    def decrypt(self, key: bytes, mac: bytes, ciphertext: bytes) -> bytes:
        """
        Decrypt data using the modem.

        Args:
            key: 32-byte decryption key.
            mac: 2-byte MAC.
            ciphertext: Encrypted data.

        Returns:
            Decrypted plaintext.

        Raises:
            RuntimeError: If decryption fails (includes MAC verification failure)
        """
        result = self._modem.decrypt_data(key, mac, ciphertext)
        if result is None:
            raise RuntimeError("Modem decryption failed (MAC verification may have failed)")
        return result

    @property
    def modem(self) -> "KissModemWrapper":
        """Get the underlying modem instance."""
        return self._modem
