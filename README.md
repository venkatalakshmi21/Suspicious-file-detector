# Suspicious File Detector — Day 2

## Features
1. File metadata collection
2. File extension analysis
3. SHA-256 hashing

The program displays the file name, absolute path, extension, size, modified time, extension category/indicator, and SHA-256 hash.

Extension indicators are clues only. An `.exe` file is not automatically malware.

## Run
```bash
python app.py
```

Use a harmless test file such as:
```text
samples/sample.txt
```

## Run tests
```bash
python -m unittest discover -s tests -v
```

## Safety
Use only harmless files you created yourself for testing. Do not execute unknown or suspicious files.
