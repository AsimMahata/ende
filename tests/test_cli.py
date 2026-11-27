"""
CLI integration and history tests using standard unittest.
Author: asim
"""

import io
import os
import shutil
import tempfile
import unittest
from pathlib import Path
from unittest.mock import patch

from ende.cli import main
from ende.history import load_history, clear_history
from ende.format import is_ende_file


class TestCLIIntegration(unittest.TestCase):

    def setUp(self):
        self.test_dir = tempfile.mkdtemp()
        self.path = Path(self.test_dir)
        os.environ["ENDE_HOME"] = str(self.path / ".ende")
        clear_history()

    def tearDown(self):
        shutil.rmtree(self.test_dir, ignore_errors=True)

    def test_cli_encrypt_decrypt_roundtrip(self):
        sample_file = self.path / "hello.txt"
        sample_content = b"Hello Asim! Testing the ende CLI."
        sample_file.write_bytes(sample_content)

        encrypted_file = self.path / "hello.txt.ende"

        # 1. Encrypt via CLI
        ret = main([str(sample_file), "-p", "TestPass123!", "-f"])
        self.assertEqual(ret, 0)
        self.assertTrue(encrypted_file.exists())
        self.assertTrue(is_ende_file(encrypted_file))

        # Remove original to test restoration
        sample_file.unlink()
        self.assertFalse(sample_file.exists())

        # 2. Decrypt via CLI (auto-detects .ende)
        ret = main([str(encrypted_file), "-p", "TestPass123!", "-f"])
        self.assertEqual(ret, 0)
        self.assertTrue(sample_file.exists())
        self.assertEqual(sample_file.read_bytes(), sample_content)

        # 3. Check history
        records = load_history()
        self.assertGreaterEqual(len(records), 2)
        self.assertEqual(records[-2]["action"], "ENCRYPT")
        self.assertEqual(records[-1]["action"], "DECRYPT")
        self.assertEqual(records[-1]["author"], "asim")

    def test_cli_double_encrypt_flag(self):
        sample_file = self.path / "double_secret.txt"
        sample_content = b"Double encryption payload via --r flag."
        sample_file.write_bytes(sample_content)

        encrypted_file = self.path / "double_secret.txt.ende"

        # Run with --r
        ret = main([
            str(sample_file),
            "--r",
            "-p", "Layer1Pass",
            "--p2", "Layer2Pass",
            "-f",
        ])
        self.assertEqual(ret, 0)
        self.assertTrue(encrypted_file.exists())

        # Delete original
        sample_file.unlink()

        # Decrypt double-encrypted file
        ret = main([
            str(encrypted_file),
            "-p", "Layer1Pass",
            "--p2", "Layer2Pass",
            "-f",
        ])
        self.assertEqual(ret, 0)
        self.assertTrue(sample_file.exists())
        self.assertEqual(sample_file.read_bytes(), sample_content)

    def test_cli_wrap_existing_ende_file_with_r(self):
        sample_file = self.path / "single.txt"
        sample_file.write_bytes(b"Testing wrapping existing .ende file with --r")
        encrypted_file = self.path / "single.txt.ende"

        # Step 1: Encrypt single layer
        ret = main([str(sample_file), "-p", "Pwd1", "-f"])
        self.assertEqual(ret, 0)

        # Step 2: Pass existing .ende file with --r
        ret = main([str(encrypted_file), "--r", "-p", "Pwd2", "-f"])
        self.assertEqual(ret, 0)

        # Remove original
        sample_file.unlink()

        # Step 3: Decrypt
        ret = main([str(encrypted_file), "-p", "Pwd1", "--p2", "Pwd2", "-f"])
        self.assertEqual(ret, 0)
        self.assertTrue(sample_file.exists())
        self.assertEqual(sample_file.read_bytes(), b"Testing wrapping existing .ende file with --r")

    def test_cli_history_and_info(self):
        sample_file = self.path / "info_test.txt"
        sample_file.write_bytes(b"Info test content")
        encrypted_file = self.path / "info_test.txt.ende"

        main([str(sample_file), "-p", "Pass1", "-f"])

        # Info command
        with patch("sys.stdout", new_callable=io.StringIO) as mock_out:
            ret = main(["info", str(encrypted_file)])
            self.assertEqual(ret, 0)
            self.assertIn("ENDE CONTAINER INFO", mock_out.getvalue())
            self.assertIn("Format Version", mock_out.getvalue())

        # History command
        with patch("sys.stdout", new_callable=io.StringIO) as mock_out:
            ret = main(["history"])
            self.assertEqual(ret, 0)
            self.assertIn("ENDE HISTORY LOG", mock_out.getvalue())

    def test_cli_version_convention(self):
        with patch("sys.stdout", new_callable=io.StringIO) as mock_out:
            with self.assertRaises(SystemExit) as cm:
                main(["--version"])
            self.assertEqual(cm.exception.code, 0)
            self.assertEqual(mock_out.getvalue().strip(), "ende 1.0.0")


if __name__ == "__main__":
    unittest.main()
