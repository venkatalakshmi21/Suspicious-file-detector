# Suspicious File Detector — Day 5

Day 5 adds a graphical user interface (GUI) and results dashboard using Python's built-in Tkinter library. It reuses the Day 3 static file analyzer and Day 4 explainable risk scorer.

## Features
- Browse for a file and click **Scan File**.
- Risk score out of 100 and LOW / MEDIUM / HIGH label.
- Dashboard with file metadata, extension category, detected signature, signature match status, modified time, and SHA-256.
- Explainable list of the warning indicators and points that contributed to the score.
- Uses only Python standard-library modules; no `pip install` required.

## Run
1. Extract this ZIP.
2. Open the `Suspicious_File_Detector_Day5` folder in VS Code.
3. Open a terminal in that folder and run:

```bash
python app.py
```

On some Linux installations Tkinter may need to be installed by the operating system package manager. On most standard Windows Python installations, Tkinter is included.

## Test
```bash
python -m unittest discover -s tests -v
```

## Safety and limitations
This is a beginner educational static-analysis project, not a professional antivirus. The risk score is a simple heuristic, not a probability that a file is malicious. A LOW score does not prove safety. Do not open or execute suspicious files to test them.
