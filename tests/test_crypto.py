"""
Unit tests for cryptographic operations and container format using standard unittest.
Author: asim
"""

import unittest
from pathlib import Path

from ende.crypto import (
    derive_key,
    encrypt_data,
    decrypt_data,
    AuthenticationError,
)
from ende.format import (
    encrypt_file_data,
    decrypt_file_data,
    wrap_existing_ende_with_layer2,
    inspect_header,
    is_ende_file,
    IntegrityError,
)


class TestCryptoAndContainer(unittest.TestCase):

    def test_crypto_roundtrip(self):
        data = b"Hello, Asim! Secret cryptographic data."
        password = "SuperStrongPassword123!"
        salt, nonce, ciphertext = encrypt_data(data, password, iterations=10_000)

        decrypted = decrypt_data(ciphertext, password, salt, nonce, iterations=10_000)
        self.assertEqual(decrypted, data)

    def test_crypto_wrong_password(self):
        data = b"Sensitive payload"
        password = "CorrectPassword"
        salt, nonce, ciphertext = encrypt_data(data, password, iterations=10_000)

        with self.assertRaises(AuthenticationError):
            decrypt_data(ciphertext, "WrongPassword", salt, nonce, iterations=10_000)

    def test_container_single_layer(self):
        original_data = b"Test single encryption container payload." * 50
        original_name = "test_doc.txt"
        password = "MySinglePassword"

        container = encrypt_file_data(
            data=original_data,
            original_name=original_name,
            password=password,
            compress=True,
            double_encrypt=False,
        )

        header = inspect_header(container)
        self.assertEqual(header["magic"], "ENDE")
        self.assertFalse(header["is_double"])
        self.assertTrue(header["is_compressed"])

        meta, restored = decrypt_file_data(container, password=password)
        self.assertEqual(restored, original_data)
        self.assertEqual(meta["original_name"], original_name)
        self.assertEqual(meta["author"], "asim")
        self.assertEqual(meta["layers"], 1)

    def test_container_double_layer(self):
        original_data = b"Double encrypted ultra secret blob." * 100
        original_name = "top_secret.dat"
        pwd1 = "Layer1_Password!"
        pwd2 = "Layer2_Password!"

        container = encrypt_file_data(
            data=original_data,
            original_name=original_name,
            password=pwd1,
            compress=True,
            double_encrypt=True,
            password2=pwd2,
        )

        header = inspect_header(container)
        self.assertTrue(header["is_double"])

        # Decrypt double layer
        meta, restored = decrypt_file_data(container, password=pwd1, password2=pwd2)
        self.assertEqual(restored, original_data)
        self.assertEqual(meta["original_name"], original_name)
        self.assertEqual(meta["layers"], 2)

    def test_wrap_existing_ende_file(self):
        original_data = b"File to be encrypted then wrapped with layer 2."
        original_name = "wrap_test.txt"
        pwd1 = "FirstPassword"
        pwd2 = "SecondPassword"

        # Single encryption first
        layer1_container = encrypt_file_data(
            data=original_data,
            original_name=original_name,
            password=pwd1,
            compress=False,
            double_encrypt=False,
        )

        # Wrap with layer 2
        layer2_container = wrap_existing_ende_with_layer2(layer1_container, pwd2)
        header = inspect_header(layer2_container)
        self.assertTrue(header["is_double"])

        # Decrypt both layers
        meta, restored = decrypt_file_data(layer2_container, password=pwd1, password2=pwd2)
        self.assertEqual(restored, original_data)

    def test_tamper_detection(self):
        data = b"Data that will be tampered."
        container = bytearray(encrypt_file_data(data, "tamper.txt", "password123"))

        # Tamper with a byte in ciphertext
        container[-5] ^= 0xFF

        with self.assertRaises(AuthenticationError):
            decrypt_file_data(bytes(container), "password123")


if __name__ == "__main__":
    unittest.main()
