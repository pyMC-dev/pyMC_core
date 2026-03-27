#!/usr/bin/env python3
"""
Test script to verify modem cryptographic operations match Python implementation.

Compares:
- Key exchange / shared secret computation
- Signing and verification
- Hashing
- Encryption/decryption
"""

import os
import sys

sys.path.insert(0, os.path.join(os.path.dirname(__file__), "..", "src"))

from pymc_core.hardware.kiss_modem_wrapper import KissModemWrapper  # noqa: E402
from pymc_core.protocol.crypto import CryptoUtils  # noqa: E402
from pymc_core.protocol.identity import Identity, LocalIdentity  # noqa: E402


def test_modem_crypto(port: str = "/dev/cu.usbmodem1101"):
    """Run cryptographic comparison tests between modem and Python."""

    print(f"Connecting to modem on {port}...")
    modem = KissModemWrapper(port=port, auto_configure=False)

    if not modem.connect():
        print("ERROR: Failed to connect to modem")
        return False

    print(f"Connected! Modem version: {modem.modem_version}")
    print(f"Modem identity: {modem.modem_identity.hex()}")
    print()

    all_passed = True

    # ==========================================================================
    # Test 1: Hash comparison
    # ==========================================================================
    print("=" * 60)
    print("Test 1: SHA-256 Hash")
    print("=" * 60)

    test_data = b"Hello, MeshCore!"

    modem_hash = modem.hash_data(test_data)
    python_hash = CryptoUtils.sha256(test_data)

    print(f"Test data: {test_data}")
    print(f"Modem hash:  {modem_hash.hex() if modem_hash else 'FAILED'}")
    print(f"Python hash: {python_hash.hex()}")

    if modem_hash == python_hash:
        print("PASS: Hashes match!")
    else:
        print("FAIL: Hashes do not match!")
        all_passed = False
    print()

    # ==========================================================================
    # Test 2: Signature verification
    # ==========================================================================
    print("=" * 60)
    print("Test 2: Sign and Verify")
    print("=" * 60)

    message = b"Test message for signing"

    # Get modem to sign
    modem_signature = modem.sign_data(message)
    print(f"Message: {message}")
    print(f"Modem signature: {modem_signature.hex() if modem_signature else 'FAILED'}")

    if modem_signature:
        # Verify with modem
        modem_verify = modem.verify_signature(modem.modem_identity, modem_signature, message)
        print(f"Modem self-verify: {modem_verify}")

        # Verify with Python using modem's public key
        modem_identity_obj = Identity(modem.modem_identity)
        python_verify = modem_identity_obj.verify(message, modem_signature)
        print(f"Python verify of modem signature: {python_verify}")

        if modem_verify and python_verify:
            print("PASS: Signature verified by both!")
        else:
            print("FAIL: Signature verification mismatch!")
            all_passed = False
    else:
        print("FAIL: Modem signing failed!")
        all_passed = False
    print()

    # ==========================================================================
    # Test 3: Key Exchange / Shared Secret
    # ==========================================================================
    print("=" * 60)
    print("Test 3: Key Exchange / Shared Secret")
    print("=" * 60)

    # Create a local identity to exchange keys with
    local_identity = LocalIdentity()
    print(f"Local identity pubkey: {local_identity.get_public_key().hex()}")
    print(f"Modem identity pubkey: {modem.modem_identity.hex()}")

    # Modem computes shared secret with local's Ed25519 pubkey
    modem_shared = modem.key_exchange(local_identity.get_public_key())
    print(f"Modem shared secret: {modem_shared.hex() if modem_shared else 'FAILED'}")

    if modem_shared:
        # Python computes shared secret: create Identity from modem's pubkey,
        # then call calc_shared_secret with local's private key
        modem_as_peer = Identity(modem.modem_identity)
        python_shared = modem_as_peer.calc_shared_secret(local_identity.get_private_key())
        print(f"Python shared secret: {python_shared.hex()}")

        if modem_shared == python_shared:
            print("PASS: Shared secrets match!")
        else:
            print("FAIL: Shared secrets do not match!")
            all_passed = False
    else:
        print("FAIL: Modem key exchange failed!")
        all_passed = False
    print()

    # ==========================================================================
    # Test 4: Encryption/Decryption round-trip
    # ==========================================================================
    print("=" * 60)
    print("Test 4: Encryption/Decryption Round-trip")
    print("=" * 60)

    if modem_shared:
        plaintext = b"Secret message for encryption test!"
        key = modem_shared  # Use the shared secret as encryption key

        print(f"Plaintext: {plaintext}")
        print(f"Key: {key.hex()[:32]}...")

        # Encrypt with modem
        encrypt_result = modem.encrypt_data(key, plaintext)
        if encrypt_result:
            mac, ciphertext = encrypt_result
            print(f"Modem encrypted - MAC: {mac.hex()}, Ciphertext: {ciphertext.hex()}")

            # Decrypt with modem
            modem_decrypted = modem.decrypt_data(key, mac, ciphertext)
            if modem_decrypted:
                # Trim padding (modem pads to block size)
                modem_decrypted = modem_decrypted[: len(plaintext)]
                print(f"Modem decrypted: {modem_decrypted}")

                if modem_decrypted == plaintext:
                    print("PASS: Modem encrypt/decrypt round-trip works!")
                else:
                    print("FAIL: Decrypted data doesn't match!")
                    all_passed = False
            else:
                print("FAIL: Modem decryption failed!")
                all_passed = False
        else:
            print("FAIL: Modem encryption failed!")
            all_passed = False

        # Now test Python encrypt -> Modem decrypt
        print()
        print("Cross-implementation test (Python encrypt -> Modem decrypt):")

        # Python encryption uses AES key (first 16 bytes) and shared secret for MAC
        aes_key = key[:16]
        python_encrypted = CryptoUtils.encrypt_then_mac(aes_key, key, plaintext)
        python_mac = python_encrypted[:2]
        python_ciphertext = python_encrypted[2:]
        print(f"Python encrypted - MAC: {python_mac.hex()}, Ciphertext: {python_ciphertext.hex()}")

        # Decrypt with modem
        modem_decrypted2 = modem.decrypt_data(key, python_mac, python_ciphertext)
        if modem_decrypted2:
            modem_decrypted2 = modem_decrypted2[: len(plaintext)]
            print(f"Modem decrypted Python ciphertext: {modem_decrypted2}")

            if modem_decrypted2 == plaintext:
                print("PASS: Cross-implementation encryption works!")
            else:
                print("FAIL: Cross-implementation decryption mismatch!")
                all_passed = False
        else:
            print("FAIL: Modem failed to decrypt Python ciphertext!")
            all_passed = False
    print()

    # ==========================================================================
    # Test 5: Random number generation
    # ==========================================================================
    print("=" * 60)
    print("Test 5: Random Number Generation")
    print("=" * 60)

    random1 = modem.get_random(32)
    random2 = modem.get_random(32)

    print(f"Random 1: {random1.hex() if random1 else 'FAILED'}")
    print(f"Random 2: {random2.hex() if random2 else 'FAILED'}")

    if random1 and random2:
        if random1 != random2:
            print("PASS: Random values are different (as expected)")
        else:
            print("FAIL: Random values are identical (suspicious!)")
            all_passed = False
    else:
        print("FAIL: Random generation failed!")
        all_passed = False
    print()

    # ==========================================================================
    # Summary
    # ==========================================================================
    print("=" * 60)
    print("SUMMARY")
    print("=" * 60)

    if all_passed:
        print("ALL TESTS PASSED!")
    else:
        print("SOME TESTS FAILED!")

    modem.disconnect()
    print("Modem disconnected.")

    return all_passed


if __name__ == "__main__":
    port = sys.argv[1] if len(sys.argv) > 1 else "/dev/cu.usbmodem1101"
    success = test_modem_crypto(port)
    sys.exit(0 if success else 1)
