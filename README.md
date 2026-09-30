# Suspicious File Detector — Day 1

## Purpose
Day 1 builds the foundation of the Suspicious File Detector. It focuses on basic static file analysis: collecting file metadata and generating a SHA-256 hash without executing the selected file.

## Features
- Reads a file path supplied by the user
- Displays file name and absolute path
- Displays file extension
- Displays file size in bytes and KB
- Generates a SHA-256 hash
- Does not execute the selected file
- Handles common file/path errors

## Project Structure
```text
suspicious_file_detector/
├── app.py
├── scanner/
│   ├── __init__.py
│   └── basic_scanner.py
├── samples/
│   └── sample.txt
├── tests/
│   └── test_basic_scanner.py
├── requirements.txt
├── .gitignore
└── README.md
```

## Requirements
Python 3.10+ is recommended. Day 1 uses only Python standard-library modules, so no external package is required.

## Run
From the project folder:

```bash
python app.py
```

Enter the path of a harmless test file when prompted.

Example:
```text
samples/sample.txt
```

## Important Safety Note
This version performs static analysis only. Do not execute or open unknown/suspicious files just to test the project. Use harmless sample files that you created yourself.

## Day 1 Scope
This version intentionally does NOT decide whether a file is malware. It only collects basic evidence. Later versions can add extension analysis, double-extension detection, file-signature checks, suspicious indicators, risk scoring, and a user interface.
