import unittest
from scanner.risk_scorer import score_file

class RiskScorerTests(unittest.TestCase):
    def test_no_indicators_is_low(self):
        result = score_file({"extension": ".txt", "extension_category": "Document", "indicators": []})
        self.assertEqual(result["risk_score"], 0)
        self.assertEqual(result["risk_level"], "LOW")
        self.assertEqual(result["reasons"], [])

    def test_double_extension_is_low_at_20(self):
        result = score_file({"extension": ".txt", "extension_category": "Document", "indicators": ["Possible double extension detected"]})
        self.assertEqual(result["risk_score"], 20)
        self.assertEqual(result["risk_level"], "LOW")

    def test_mismatch_and_unknown_can_be_medium(self):
        result = score_file({"extension": ".jpg", "extension_category": "Image", "indicators": ["File extension .jpg does not match detected signature type (PDF document)"]})
        self.assertEqual(result["risk_score"], 30)
        self.assertEqual(result["risk_level"], "MEDIUM")

    def test_multiple_indicators_can_be_high(self):
        result = score_file({"extension": ".exe", "extension_category": "Executable", "indicators": ["Possible double extension detected", "Executable/script extension detected: .exe", "File extension .exe does not match detected signature type (PDF document)"]})
        self.assertEqual(result["risk_score"], 70)
        self.assertEqual(result["risk_level"], "HIGH")
        self.assertEqual(len(result["reasons"]), 3)

if __name__ == "__main__":
    unittest.main()
