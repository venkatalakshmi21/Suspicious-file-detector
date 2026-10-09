from scanner.file_analyzer import analyze_file

def main():
    print("=" * 70)
    print("          SUSPICIOUS FILE DETECTOR - DAY 3")
    print("=" * 70)
    print("Features: metadata + extension + SHA-256 +")
    print("double-extension detection + signature analysis + indicators\n")
    file_path = input("Enter the path of a harmless test file: ").strip()
    if not file_path:
        print("No file path was entered."); return
    try:
        result = analyze_file(file_path)
        print("\n" + "-" * 70)
        print("FILE ANALYSIS RESULT")
        print("-" * 70)
        print("\n[FILE METADATA]")
        print(f"File Name       : {result['file_name']}")
        print(f"Absolute Path   : {result['absolute_path']}")
        print(f"Extension       : {result['extension'] or '[none]'}")
        print(f"Size            : {result['size_bytes']} bytes")
        print(f"Size            : {result['size_kb']:.2f} KB")
        print(f"Modified        : {result['modified_time']}")
        print("\n[EXTENSION ANALYSIS]")
        print(f"Category        : {result['extension_category']}")
        print(f"Extension Note  : {result['extension_indicator']}")
        print("\n[DOUBLE-EXTENSION CHECK]")
        print(f"Detected        : {'YES' if result['double_extension'] else 'NO'}")
        if result['double_extension']:
            print(f"Possible extensions: {', '.join(result['detected_extensions'])}")
        print("\n[FILE SIGNATURE ANALYSIS]")
        print(f"Detected Type   : {result['signature_type']}")
        print(f"Signature Match : {result['signature_match']}")
        print("\n[SUSPICIOUS INDICATORS]")
        if result['indicators']:
            for indicator in result['indicators']: print(f"⚠ {indicator}")
        else: print("✓ No Day 3 indicators detected.")
        print("\n[SHA-256]")
        print(result['sha256'])
        print("\n" + "-" * 70)
        print("Day 3 analysis completed.")
        print("IMPORTANT: Indicators are clues, not proof of malware.")
        print("-" * 70)
    except FileNotFoundError: print("Error: File not found. Check the path and try again.")
    except PermissionError: print("Error: Permission denied while reading the file.")
    except IsADirectoryError: print("Error: You entered a directory, not a file.")
    except OSError as exc: print(f"Error while analyzing the file: {exc}")

if __name__ == "__main__": main()
