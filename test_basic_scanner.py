import hashlib
import tempfile
import unittest
from pathlib import Path

from scanner.basic_scanner import calculate_sha256, scan_file


class TestBasicScanner(unittest.TestCase):

    def test_sha256(self):
        with tempfile.TemporaryDirectory() as temp_dir:
            file_path = Path(temp_dir) / "sample.txt"
            file_path.write_text("hello", encoding="utf-8")

            expected = hashlib.sha256(b"hello").hexdigest()
            self.assertEqual(calculate_sha256(file_path), expected)

    def test_scan_file_metadata(self):
        with tempfile.TemporaryDirectory() as temp_dir:
            file_path = Path(temp_dir) / "sample.txt"
            file_path.write_text("hello", encoding="utf-8")

            result = scan_file(file_path)

            self.assertEqual(result["file_name"], "sample.txt")
            self.assertEqual(result["extension"], ".txt")
            self.assertEqual(result["size_bytes"], 5)
            self.assertIn("sha256", result)

    def test_missing_file(self):
        with self.assertRaises(FileNotFoundError):
            scan_file("this_file_does_not_exist.txt")


if __name__ == "__main__":
    unittest.main()
