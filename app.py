"""Day 4 demo: explainable risk scoring for a selected file."""
from pathlib import Path
from scanner.file_analyzer import analyze_file
from scanner.risk_scorer import score_file


def main() -> None:
    print("=" * 58)
    print(" SUSPICIOUS FILE DETECTOR — DAY 4 RISK SCORING")
    print("=" * 58)
    raw_path = input("Enter the path of a file to analyze: ").strip().strip('"')
    path = Path(raw_path).expanduser()
    try:
        analysis = analyze_file(path)
        result = score_file(analysis)
    except (OSError, ValueError, KeyError, TypeError) as exc:
        print(f"Could not analyze this file: {exc}")
        return

    print(f"\nFile: {analysis['file_name']}")
    print(f"SHA-256: {analysis['sha256']}")
    print("\n--- RISK RESULT ---")
    print(f"Score: {result['risk_score']}/100")
    print(f"Level: {result['risk_level']}")
    print(result['summary'])
    print("\n--- WHY THIS SCORE? ---")
    if result['reasons']:
        for item in result['reasons']:
            print(f"+{item['points']} points — {item['explanation']}")
    else:
        print("No configured warning indicators were triggered.")
    print("\nNote: This is a basic educational heuristic, not an antivirus verdict.")
    print("Do not open or execute a suspicious file just to test it.")


if __name__ == "__main__":
    main()
