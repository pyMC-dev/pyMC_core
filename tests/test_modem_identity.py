"""
Tests for ModemIdentity class

Tests the modem-based identity that delegates cryptographic operations
to the KISS modem hardware.
"""

from unittest.mock import MagicMock

import pytest
from nacl.signing import SigningKey

from pymc_core.protocol.modem_identity import ModemIdentity

# Generate a valid Ed25519 keypair for testing
_TEST_SIGNING_KEY = SigningKey.generate()
_TEST_PUBKEY = bytes(_TEST_SIGNING_KEY.verify_key)


@pytest.fixture
def mock_modem():
    """Create a mock KISS modem with standard responses"""
    modem = MagicMock()
    modem.is_connected = True

    # Use a valid Ed25519 public key
    modem.get_identity.return_value = _TEST_PUBKEY
    modem.modem_identity = _TEST_PUBKEY

    return modem


@pytest.fixture
def modem_identity(mock_modem):
    """Create a ModemIdentity with mock modem"""
    return ModemIdentity(mock_modem)


class TestModemIdentityInit:
    """Test ModemIdentity initialization"""

    def test_init_requires_connected_modem(self):
        """Test that init fails if modem is not connected"""
        modem = MagicMock()
        modem.is_connected = False

        with pytest.raises(ValueError, match="must be connected"):
            ModemIdentity(modem)

    def test_init_requires_valid_identity(self):
        """Test that init fails if modem returns invalid identity"""
        modem = MagicMock()
        modem.is_connected = True
        modem.get_identity.return_value = None

        with pytest.raises(ValueError, match="Failed to retrieve"):
            ModemIdentity(modem)

    def test_init_requires_32_byte_pubkey(self):
        """Test that init fails if pubkey is wrong size"""
        modem = MagicMock()
        modem.is_connected = True
        modem.get_identity.return_value = bytes(16)  # Too short

        with pytest.raises(ValueError, match="Failed to retrieve"):
            ModemIdentity(modem)

    def test_init_success(self, mock_modem):
        """Test successful initialization"""
        identity = ModemIdentity(mock_modem)

        assert identity.get_public_key() == _TEST_PUBKEY
        mock_modem.get_identity.assert_called_once()


class TestModemIdentityPublicKey:
    """Test public key operations"""

    def test_get_public_key(self, modem_identity):
        """Test getting the public key"""
        pubkey = modem_identity.get_public_key()
        assert len(pubkey) == 32
        assert pubkey == _TEST_PUBKEY

    def test_get_address_bytes(self, modem_identity):
        """Test getting address bytes (first byte of SHA256)"""
        address = modem_identity.get_address_bytes()
        assert len(address) == 1

    def test_get_shared_public_key(self, modem_identity):
        """Test getting X25519 public key"""
        x25519_pubkey = modem_identity.get_shared_public_key()
        assert len(x25519_pubkey) == 32


class TestModemIdentitySigning:
    """Test signing operations"""

    def test_sign_delegates_to_modem(self, modem_identity, mock_modem):
        """Test that signing delegates to modem"""
        signature = bytes(range(64))
        mock_modem.sign_data.return_value = signature

        result = modem_identity.sign(b"test message")

        assert result == signature
        mock_modem.sign_data.assert_called_once_with(b"test message")

    def test_sign_raises_on_failure(self, modem_identity, mock_modem):
        """Test that sign raises RuntimeError on failure"""
        mock_modem.sign_data.return_value = None

        with pytest.raises(RuntimeError, match="signing failed"):
            modem_identity.sign(b"test message")


class TestModemIdentityVerification:
    """Test signature verification"""

    def test_verify_delegates_to_modem(self, modem_identity, mock_modem):
        """Test that verification delegates to modem"""
        mock_modem.verify_signature.return_value = True

        result = modem_identity.verify(b"message", bytes(64))

        assert result is True
        mock_modem.verify_signature.assert_called_once()

    def test_verify_returns_false_on_invalid(self, modem_identity, mock_modem):
        """Test that verify returns False for invalid signature"""
        mock_modem.verify_signature.return_value = False

        result = modem_identity.verify(b"message", bytes(64))

        assert result is False


class TestModemIdentityKeyExchange:
    """Test ECDH key exchange"""

    def test_calc_shared_secret_delegates_to_modem(self, modem_identity, mock_modem):
        """Test that key exchange delegates to modem"""
        shared_secret = bytes(range(32))
        mock_modem.key_exchange.return_value = shared_secret

        result = modem_identity.calc_shared_secret(bytes(32))

        assert result == shared_secret
        mock_modem.key_exchange.assert_called_once()

    def test_calc_shared_secret_raises_on_failure(self, modem_identity, mock_modem):
        """Test that key exchange raises RuntimeError on failure"""
        mock_modem.key_exchange.return_value = None

        with pytest.raises(RuntimeError, match="key exchange failed"):
            modem_identity.calc_shared_secret(bytes(32))


class TestModemIdentityPrivateKeyProtection:
    """Test that private keys are not exposed"""

    def test_get_private_key_raises(self, modem_identity):
        """Test that get_private_key raises RuntimeError"""
        with pytest.raises(RuntimeError, match="does not expose private keys"):
            modem_identity.get_private_key()

    def test_get_signing_key_bytes_raises(self, modem_identity):
        """Test that get_signing_key_bytes raises RuntimeError"""
        with pytest.raises(RuntimeError, match="does not expose signing keys"):
            modem_identity.get_signing_key_bytes()


class TestModemIdentityEncryption:
    """Test encryption operations"""

    def test_encrypt_delegates_to_modem(self, modem_identity, mock_modem):
        """Test that encryption delegates to modem"""
        mac = bytes([0x01, 0x02])
        ciphertext = bytes(range(16))
        mock_modem.encrypt_data.return_value = (mac, ciphertext)

        result = modem_identity.encrypt(bytes(32), b"plaintext")

        assert result == (mac, ciphertext)
        mock_modem.encrypt_data.assert_called_once()

    def test_encrypt_raises_on_failure(self, modem_identity, mock_modem):
        """Test that encrypt raises RuntimeError on failure"""
        mock_modem.encrypt_data.return_value = None

        with pytest.raises(RuntimeError, match="encryption failed"):
            modem_identity.encrypt(bytes(32), b"plaintext")


class TestModemIdentityDecryption:
    """Test decryption operations"""

    def test_decrypt_delegates_to_modem(self, modem_identity, mock_modem):
        """Test that decryption delegates to modem"""
        plaintext = b"decrypted data"
        mock_modem.decrypt_data.return_value = plaintext

        result = modem_identity.decrypt(bytes(32), bytes(2), bytes(16))

        assert result == plaintext
        mock_modem.decrypt_data.assert_called_once()

    def test_decrypt_raises_on_failure(self, modem_identity, mock_modem):
        """Test that decrypt raises RuntimeError on failure (MAC failure)"""
        mock_modem.decrypt_data.return_value = None

        with pytest.raises(RuntimeError, match="decryption failed"):
            modem_identity.decrypt(bytes(32), bytes(2), bytes(16))


class TestModemIdentityHashing:
    """Test hashing operations"""

    def test_hash_delegates_to_modem(self, modem_identity, mock_modem):
        """Test that hashing delegates to modem"""
        hash_result = bytes(range(32))
        mock_modem.hash_data.return_value = hash_result

        result = modem_identity.hash_data(b"data to hash")

        assert result == hash_result
        mock_modem.hash_data.assert_called_once_with(b"data to hash")

    def test_hash_falls_back_to_local(self, modem_identity, mock_modem):
        """Test that hashing falls back to local on modem failure"""
        mock_modem.hash_data.return_value = None

        result = modem_identity.hash_data(b"data to hash")

        # Should still return a 32-byte hash (local fallback)
        assert len(result) == 32


class TestModemIdentityRandom:
    """Test random number generation"""

    def test_get_random_delegates_to_modem(self, modem_identity, mock_modem):
        """Test that random generation delegates to modem"""
        random_bytes = bytes(range(16))
        mock_modem.get_random.return_value = random_bytes

        result = modem_identity.get_random(16)

        assert result == random_bytes
        mock_modem.get_random.assert_called_once_with(16)

    def test_get_random_raises_on_failure(self, modem_identity, mock_modem):
        """Test that get_random raises RuntimeError on failure"""
        mock_modem.get_random.return_value = None

        with pytest.raises(RuntimeError, match="random generation failed"):
            modem_identity.get_random(16)


class TestModemIdentityModemAccess:
    """Test modem access property"""

    def test_modem_property(self, modem_identity, mock_modem):
        """Test that modem property returns the underlying modem"""
        assert modem_identity.modem is mock_modem
