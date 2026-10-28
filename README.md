# Suspicious File Detector — Day 4

A beginner-friendly Python cybersecurity mini-project that performs static file checks and explains a simple risk score.

## Day 4 features
- Uses Day 3 metadata, SHA-256, extension, double-extension, and signature checks.
- Applies a transparent rule-based score from 0 to 100.
- Labels results LOW, MEDIUM, or HIGH.
- Explains every triggered rule in plain language.
- Includes unit tests; uses Python standard library only.

## Setup and run
Python 3.10+ recommended. No extra packages are required.

```bash
python app.py
```
Enter a sample path such as `samples/mismatch.jpg` when prompted.

Run tests:
```bash
python -m unittest discover -s tests -v
```

## Important limitation
The risk score is a teaching heuristic, not a malware probability or antivirus verdict. A low score does not prove a file is safe; a high score does not prove it is malware. Do not execute suspicious files.
