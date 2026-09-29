from scanner.basic_scanner import scan_file


def main():
    print("=" * 50)
    print("       SUSPICIOUS FILE DETECTOR - DAY 1")
    print("=" * 50)
    print("Static analysis only: the selected file is NOT executed.\n")

    file_path = input("Enter the path of a harmless test file: ").strip()

    if not file_path:
        print("No file path was entered.")
        return

    try:
        result = scan_file(file_path)

        print("\n" + "-" * 50)
        print("FILE ANALYSIS RESULT")
        print("-" * 50)
        print(f"File Name : {result['file_name']}")
        print(f"Path      : {result['absolute_path']}")
        print(f"Extension : {result['extension'] or '[none]'}")
        print(f"Size      : {result['size_bytes']} bytes")
        print(f"Size      : {result['size_kb']:.2f} KB")
        print(f"SHA-256   : {result['sha256']}")
        print("-" * 50)
        print("Day 1 result: File information collected successfully.")
        print("No malware/safety verdict is made in this version.")

    except FileNotFoundError:
        print("Error: The file was not found. Check the path and try again.")
    except PermissionError:
        print("Error: Permission denied while reading the file.")
    except IsADirectoryError:
        print("Error: You entered a directory, not a file.")
    except OSError as exc:
        print(f"Error while reading the file: {exc}")


if __name__ == "__main__":
    main()
