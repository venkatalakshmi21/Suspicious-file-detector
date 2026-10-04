import hashlib
import tempfile
import unittest
from pathlib import Path
from scanner.file_analyzer import analyze_extension, analyze_file, calculate_sha256

class TestFileAnalyzer(unittest.TestCase):
    def test_sha256(self):
        with tempfile.TemporaryDirectory() as temp_dir:
            file_path = Path(temp_dir) / "sample.txt"
            file_path.write_text("hello", encoding="utf-8")
            expected = hashlib.sha256(b"hello").hexdigest()
            self.assertEqual(calculate_sha256(file_path), expected)

    def test_document_extension(self):
        category, indicator = analyze_extension(".pdf")
        self.assertEqual(category, "Document")
        self.assertEqual(indicator, "Normal document type")

    def test_executable_extension(self):
        category, indicator = analyze_extension(".exe")
        self.assertEqual(category, "Executable")
        self.assertEqual(indicator, "Review carefully")

    def test_metadata(self):
        with tempfile.TemporaryDirectory() as temp_dir:
            file_path = Path(temp_dir) / "sample.pdf"
            file_path.write_text("hello", encoding="utf-8")
            result = analyze_file(file_path)
            self.assertEqual(result["file_name"], "sample.pdf")
            self.assertEqual(result["extension"], ".pdf")
            self.assertEqual(result["size_bytes"], 5)
            self.assertTrue(len(result["sha256"]) == 64)

    def test_missing_file(self):
        with self.assertRaises(FileNotFoundError):
            analyze_file("file_that_does_not_exist.pdf")

if __name__ == "__main__":
    unittest.main()
