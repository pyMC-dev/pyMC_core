from typing import Optional

from nacl.exceptions import BadSignatureError
from nacl.public import PublicKey
from nacl.signing import SigningKey, VerifyKey

from . import CryptoUtils

# ---------------------------------------------------------------------------
# Identity classes -----------------------------------------------------------
# ---------------------------------------------------------------------------


class Identity:
    """
    Represents a peer's public identity for cryptographic operations.

    Handles Ed25519 public key operations including signature verification
    and ECDH shared secret computation. Instances are immutable and thread-safe.
    """

    def __init__(self, ed25519_public_key: bytes):
        """
        Initialise an Identity instance for a peer.

        Creates an identity object from the peer's Ed25519 public key,
        enabling signature verification and shared secret computation.

        Args:
            ed25519_public_key: The peer's 32-byte Ed25519 public key.
        """
        self.verify_key = VerifyKey(ed25519_public_key)
        self.x25519_pubkey = PublicKey(CryptoUtils.ed25519_pk_to_x25519(ed25519_public_key))

    def verify(self, message: bytes, signature: bytes) -> bool:
        """
        Verify a signature against a message using the peer's public key.

        Args:
            message: The original message bytes.
            signature: The signature to verify.

        Returns:
            True if the signature is valid, False otherwise.
        """
        try:
            self.verify_key.verify(message, signature)
            return True
        except BadSignatureError:
            return False

    def get_public_key(self) -> bytes:
        """
        Get the Ed25519 public key for this identity.

        Returns:
            The 32-byte Ed25519 public key.
        """
        return self.verify_key.encode()

    def calc_shared_secret(self, local_private_x25519: bytes) -> bytes:
        """
        Compute the ECDH shared secret with a local private key.

        Args:
            local_private_x25519: The local X25519 private key.

        Returns:
            The 32-byte shared secret for encryption.
        """
        return CryptoUtils.scalarmult(local_private_x25519, self.x25519_pubkey.encode())


# ---------------------------------------------------------------------------
# LocalIdentity class --------------------------------------------------------
# ---------------------------------------------------------------------------


class LocalIdentity(Identity):
    """
    Represents the local node's cryptographic identity with full key access.

    Extends Identity with private key operations for signing and ECDH.
    Generates or derives Ed25519 and X25519 key pairs for secure communication.
    """

    def __init__(self, seed: Optional[bytes] = None):
        """
        Initialise a LocalIdentity instance with signing and encryption keys.

        Creates a local identity with Ed25519 and X25519 key pairs for
        digital signatures and ECDH key agreement. If no seed is provided,
        generates a new random key pair.

        Args:
            seed: Optional 32 or 64-byte seed. 32-byte for standard PyNaCl key generation,
                  64-byte for MeshCore firmware expanded key format [scalar||nonce].
        """
        # Detect MeshCore 64-byte expanded key format
        if seed and len(seed) == 64:
            from nacl.bindings import crypto_scalarmult_ed25519_base_noclamp

            # MeshCore format: [32-byte scalar][32-byte nonce]. Identity.cpp readFrom(64) calls
            # ed25519_derive_pub(pub_key, prv_key) which uses first 32 bytes as-is (no clamp).
            # key_exchange.c uses first 32 bytes clamped for ECDH. We must match both.
            self._firmware_key = seed
            self.signing_key = None

            scalar_first32 = seed[:32]
            # Ed25519 public: derive without clamping so get_public_key() matches firmware
            ed25519_pub = crypto_scalarmult_ed25519_base_noclamp(scalar_first32)
            self.verify_key = VerifyKey(ed25519_pub)

            # ECDH: use clamped scalar so shared secret matches firmware's ed25519_key_exchange()
            clamped = CryptoUtils.x25519_clamp_scalar(scalar_first32)
            self._x25519_private = clamped
            self._x25519_public = CryptoUtils.scalarmult_base(clamped)
        else:
            # Standard 32-byte seed or None
            self._firmware_key = None
            self.signing_key = SigningKey(seed) if seed else SigningKey.generate()
            self.verify_key = self.signing_key.verify_key

            # Build 64-byte Ed25519 secret key: seed + pub
            ed25519_pub = self.verify_key.encode()
            ed25519_sk = self.signing_key.encode() + ed25519_pub

            # X25519 keypair for ECDH (libsodium conversion)
            self._x25519_private = CryptoUtils.ed25519_sk_to_x25519(ed25519_sk)
            self._x25519_public = CryptoUtils.scalarmult_base(self._x25519_private)

        # Initialise base class with Ed25519 pubkey
        super().__init__(ed25519_pub)

    def get_address_bytes(self) -> bytes:
        """
        Get the address bytes derived from the public key.

        Returns:
            The first byte of SHA256 hash of the public key, used as address.
        """
        # Address is the first byte of SHA256(pubkey)
        return CryptoUtils.sha256(self.get_public_key())[:1]

    def get_private_key(self) -> bytes:
        """
        Get the X25519 private key for ECDH operations.

        Returns:
            The 32-byte X25519 private key.
        """
        return self._x25519_private

    def get_shared_public_key(self) -> bytes:
        """
        Get the X25519 public key for ECDH operations.

        Returns:
            The 32-byte X25519 public key.
        """
        return self._x25519_public

    def get_signing_key_bytes(self) -> bytes:
        """
        Get the signing key bytes for this identity.

        For standard keys, returns the 32-byte Ed25519 seed.
        For firmware keys, returns the 64-byte expanded key format [scalar||nonce].

        Returns:
            The signing key bytes (32 or 64 bytes depending on key type).
        """
        if self._firmware_key:
            return self._firmware_key
        return self.signing_key.encode()

    def sign(self, message: bytes) -> bytes:
        """
        Sign a message with the Ed25519 private key.

        Args:
            message: The message to sign.

        Returns:
            The 64-byte Ed25519 signature.
        """
        if self._firmware_key:
            # Use MeshCore/orlp ed25519 signing algorithm
            import hashlib

            from nacl.bindings import (
                crypto_core_ed25519_scalar_add,
                crypto_core_ed25519_scalar_mul,
                crypto_core_ed25519_scalar_reduce,
                crypto_scalarmult_ed25519_base_noclamp,
            )

            scalar = self._firmware_key[:32]
            nonce_prefix = self._firmware_key[32:64]
            public_key = self.get_public_key()

            # r = H(nonce_prefix || message)
            r_hash = hashlib.sha512(nonce_prefix + message).digest()
            r = crypto_core_ed25519_scalar_reduce(r_hash)

            # R = r * G
            R_point = crypto_scalarmult_ed25519_base_noclamp(r)

            # h = H(R || pubkey || message)
            h_hash = hashlib.sha512(R_point + public_key + message).digest()
            h = crypto_core_ed25519_scalar_reduce(h_hash)

            # s = (h * scalar + r) mod L
            h_times_scalar = crypto_core_ed25519_scalar_mul(h, scalar)
            s = crypto_core_ed25519_scalar_add(h_times_scalar, r)

            # Signature is R || s
            return R_point + s

        return self.signing_key.sign(message).signature
