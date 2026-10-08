import hashlib,tempfile,unittest
from pathlib import Path
from scanner.file_analyzer import analyze_file,analyze_extension,calculate_sha256,detect_double_extension,detect_signature

class TestFileAnalyzer(unittest.TestCase):
    def test_sha256(self):
        with tempfile.TemporaryDirectory() as d:
            p=Path(d)/"sample.txt"; p.write_text("hello",encoding="utf-8")
            self.assertEqual(calculate_sha256(p),hashlib.sha256(b"hello").hexdigest())
    def test_document_extension(self):
        self.assertEqual(analyze_extension(".pdf"),("Document","Normal document type"))
    def test_double_extension(self):
        detected,extensions=detect_double_extension("invoice.pdf.exe")
        self.assertTrue(detected); self.assertIn(".pdf",extensions); self.assertIn(".exe",extensions)
    def test_normal_extension(self): self.assertFalse(detect_double_extension("photo.jpg")[0])
    def test_pdf_signature(self):
        with tempfile.TemporaryDirectory() as d:
            p=Path(d)/"sample.pdf"; p.write_bytes(b"%PDF-1.7\nhello")
            self.assertEqual(detect_signature(p),("PDF document",".pdf"))
    def test_signature_mismatch(self):
        with tempfile.TemporaryDirectory() as d:
            p=Path(d)/"picture.jpg"; p.write_bytes(b"%PDF-1.7\nhello")
            r=analyze_file(p); self.assertEqual(r["signature_match"],"MISMATCH"); self.assertTrue(r["indicators"])
    def test_full_analysis(self):
        with tempfile.TemporaryDirectory() as d:
            p=Path(d)/"sample.pdf"; p.write_bytes(b"%PDF-1.7\nhello")
            r=analyze_file(p); self.assertEqual(r["signature_match"],"MATCH"); self.assertEqual(len(r["sha256"]),64)
    def test_missing_file(self):
        with self.assertRaises(FileNotFoundError): analyze_file("file_that_does_not_exist.pdf")

if __name__=="__main__": unittest.main()
