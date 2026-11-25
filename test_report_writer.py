import json
import tempfile
import unittest
from pathlib import Path
from scanner.report_writer import save_json_report, save_text_report, build_report

ANALYSIS = {"file_name": "sample.txt", "absolute_path": "/tmp/sample.txt", "size_bytes": 10,
            "extension": ".txt", "signature_type": "Unknown signature", "signature_match": "Unknown", "sha256": "abc123"}
RESULT = {"risk_score": 10, "risk_level": "LOW", "summary": "Example summary", "reasons": []}

class ReportWriterTests(unittest.TestCase):
    def test_build_report_contains_analysis_and_result(self):
        report = build_report(ANALYSIS, RESULT)
        self.assertEqual(report["file_analysis"], ANALYSIS)
        self.assertEqual(report["risk_assessment"], RESULT)
        self.assertIn("disclaimer", report)

    def test_save_json_report(self):
        with tempfile.TemporaryDirectory() as folder:
            target = Path(folder) / "reports" / "scan.json"
            saved = save_json_report(ANALYSIS, RESULT, target)
            data = json.loads(saved.read_text(encoding="utf-8"))
            self.assertEqual(data["risk_assessment"]["risk_level"], "LOW")

    def test_save_text_report(self):
        with tempfile.TemporaryDirectory() as folder:
            target = Path(folder) / "scan.txt"
            saved = save_text_report(ANALYSIS, RESULT, target)
            content = saved.read_text(encoding="utf-8")
            self.assertIn("Risk score: 10/100", content)
            self.assertIn("does not guarantee safety", content)

    def test_report_write_error_for_directory_destination(self):
        with tempfile.TemporaryDirectory() as folder:
            with self.assertRaises((IsADirectoryError, PermissionError, OSError)):
                save_text_report(ANALYSIS, RESULT, folder)

if __name__ == "__main__": unittest.main()
