"""Explainable risk scoring for the Suspicious File Detector (Day 4).

This is a learning/demo heuristic, not an antivirus verdict.
"""
from typing import Any, Dict, List

# Risk points are illustrative and can be tuned as the project develops.
RULES = [
    ("possible_double_extension", 20, "The filename contains multiple extension-like parts."),
    ("executable_or_script_extension", 20, "The file extension is commonly associated with executable or script files."),
    ("extension_signature_mismatch", 30, "The file content signature does not match its filename extension."),
    ("unknown_signature", 10, "The file type could not be identified from the small set of signatures checked."),
]


def score_file(analysis: Dict[str, Any]) -> Dict[str, Any]:
    """Score an analysis dictionary from Day 3 and return score, level, reasons.

    Expected keys include ``indicators`` (list of strings) and ``extension``
    (string or extension-analysis dict). Missing fields are handled safely.
    """
    indicators = set(analysis.get("indicators") or [])
    extension_info = analysis.get("extension", analysis.get("extension_category", ""))
    if isinstance(extension_info, dict):
        extension = str(extension_info.get("extension", "")).lower()
        category = str(extension_info.get("category", "")).lower()
    else:
        extension = str(analysis.get("extension", "")).lower()
        category = str(analysis.get("extension_category", extension_info)).lower()

    # Support either Day 3 indicator labels or deriving executable status from extension/category.
    executable_exts = {".exe", ".dll", ".bat", ".cmd", ".com", ".msi", ".ps1", ".vbs", ".js", ".sh", ".py"}
    checks = {
        "possible_double_extension": "possible_double_extension" in indicators or "double extension" in " ".join(indicators).lower(),
        "executable_or_script_extension": (
            "executable_or_script_extension" in indicators
            or "executable" in " ".join(indicators).lower()
            or "script" in " ".join(indicators).lower()
            or extension in executable_exts
            or category in {"executable", "script"}
        ),
        "extension_signature_mismatch": "extension_signature_mismatch" in indicators or "mismatch" in " ".join(indicators).lower() or "does not match" in " ".join(indicators).lower(),
        "unknown_signature": "unknown_signature" in indicators or "unknown signature" in " ".join(indicators).lower(),
    }

    score = 0
    reasons: List[Dict[str, Any]] = []
    for key, points, explanation in RULES:
        if checks[key]:
            score += points
            reasons.append({"indicator": key, "points": points, "explanation": explanation})

    score = min(score, 100)
    if score <= 20:
        level = "LOW"
        summary = "Few warning indicators were detected by these basic checks. This does not prove the file is safe."
    elif score <= 49:
        level = "MEDIUM"
        summary = "Some warning indicators were detected. Review the reasons and verify the file source."
    else:
        level = "HIGH"
        summary = "Several or stronger warning indicators were detected. Do not open or execute the file until it has been reviewed."

    if not reasons:
        summary = "No configured warning indicators were detected. This does not prove the file is safe."

    return {"risk_score": score, "risk_level": level, "summary": summary, "reasons": reasons}
