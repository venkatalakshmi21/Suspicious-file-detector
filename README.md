# Suspicious File Detector — Day 3

## Features
- File metadata
- Extension analysis
- SHA-256 hashing
- Double-extension detection
- File-signature (magic-number) analysis
- Suspicious-indicator reporting

### Double Extension
Examples such as `invoice.pdf.exe` can be flagged as suspicious. This is only a clue, not proof of malware.

### Signature Analysis
The scanner reads only the first few bytes and checks common signatures: PDF, PNG, JPEG, GIF, ZIP, and Windows PE/executable family. It never executes the file.

### Mismatch
If a filename says `.jpg` but the file begins with a PDF signature, the result is `MISMATCH`.

### Run
```bash
python app.py
```
Safe test files:
```text
samples/sample.txt
samples/invoice.pdf.exe.txt
samples/mismatch.jpg
```

### Tests
```bash
python -m unittest discover -s tests -v
```

## Safety
Use harmless files created by you for testing. Do not execute unknown or suspicious files. Indicators are not a malware verdict.
