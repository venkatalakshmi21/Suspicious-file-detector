import tempfile
import unittest
from pathlib import Path
from scanner.file_analyzer import analyze_file

class ErrorHandlingTests(unittest.TestCase):
    def test_missing_file_raises_file_not_found(self):
        with self.assertRaises(FileNotFoundError): analyze_file("this_file_does_not_exist_12345.bin")

    def test_directory_is_not_scanned_as_file(self):
        with tempfile.TemporaryDirectory() as folder:
            with self.assertRaises(IsADirectoryError): analyze_file(folder)

    def test_empty_file_can_be_analyzed(self):
        with tempfile.TemporaryDirectory() as folder:
            path = Path(folder) / "empty.txt"; path.write_bytes(b"")
            result = analyze_file(path)
            self.assertEqual(result["size_bytes"], 0)
            self.assertEqual(len(result["sha256"]), 64)

if __name__ == "__main__": unittest.main()
