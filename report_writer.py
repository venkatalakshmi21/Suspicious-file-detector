"""Create readable TXT and JSON reports for a completed scan."""
import json
from datetime import datetime
from pathlib import Path
from typing import Any, Dict


def build_report(analysis: Dict[str, Any], result: Dict[str, Any]) -> Dict[str, Any]:
    return {
        "report_created": datetime.now().astimezone().isoformat(timespec="seconds"),
        "tool": "Suspicious File Detector",
        "disclaimer": "Educational static-analysis result; not proof that a file is safe or malicious.",
        "file_analysis": analysis,
        "risk_assessment": result,
    }


def save_json_report(analysis: Dict[str, Any], result: Dict[str, Any], destination) -> Path:
    path = Path(destination).expanduser()
    path.parent.mkdir(parents=True, exist_ok=True)
    report = build_report(analysis, result)
    path.write_text(json.dumps(report, indent=4, ensure_ascii=False), encoding="utf-8")
    return path


def save_text_report(analysis: Dict[str, Any], result: Dict[str, Any], destination) -> Path:
    path = Path(destination).expanduser()
    path.parent.mkdir(parents=True, exist_ok=True)
    lines = [
        "SUSPICIOUS FILE DETECTOR - SCAN REPORT",
        "=" * 42,
        f"File name: {analysis.get('file_name', 'Unknown')}",
        f"Path: {analysis.get('absolute_path', 'Unknown')}",
        f"Size: {analysis.get('size_bytes', 'Unknown')} bytes",
        f"Extension: {analysis.get('extension') or '[none]' }",
        f"Detected format: {analysis.get('signature_type', 'Unknown')}",
        f"Signature check: {analysis.get('signature_match', 'Unknown')}",
        f"SHA-256: {analysis.get('sha256', 'Unknown')}",
        "",
        f"Risk score: {result.get('risk_score', 0)}/100",
        f"Risk level: {result.get('risk_level', 'UNKNOWN')}",
        f"Summary: {result.get('summary', '')}",
        "",
        "REASONS",
        "-------",
    ]
    reasons = result.get("reasons") or []
    if reasons:
        for item in reasons:
            lines.append(f"+{item.get('points', 0)} points | {item.get('indicator', 'indicator')}: {item.get('explanation', '')}")
    else:
        lines.append("No configured warning indicators were triggered.")
    lines += ["", "NOTE: This educational heuristic is not an antivirus verdict. LOW risk does not guarantee safety."]
    path.write_text("\n".join(lines) + "\n", encoding="utf-8")
    return path
