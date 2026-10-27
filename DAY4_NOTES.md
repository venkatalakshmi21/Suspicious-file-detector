# Day 4 Notes — Risk Scoring Engine

## What you added
The scanner now converts selected warning indicators into a score from 0 to 100, a LOW/MEDIUM/HIGH level, and plain-language reasons.

## Current demo rules
- Possible double extension: +20
- Executable/script extension: +20
- Extension/signature mismatch: +30
- Unknown signature: +10
- Score is capped at 100.

## Levels
- **LOW:** 0–20
- **MEDIUM:** 21–49
- **HIGH:** 50–100

These thresholds and points are illustrative project rules, not scientifically validated malware probabilities. The score means "how many configured warning signs were found," not "probability the file is malware." A LOW score does not mean safe.

## Explainable results
For each rule that adds points, the program prints the indicator, points added, and a plain-language reason. This makes it easier for a user or project evaluator to understand the result.

## Run
From this folder:
```bash
python app.py
```
Try these harmless samples when prompted:
- `samples/sample.txt`
- `samples/invoice.pdf.exe.txt`
- `samples/mismatch.jpg`

Run all tests:
```bash
python -m unittest discover -s tests -v
```

## Safety
This is an educational static-analysis demo, not an antivirus. Never open or execute a suspicious file just to test it. The sample files are harmless demonstration files.
