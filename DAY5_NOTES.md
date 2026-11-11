# Day 5 Notes — UI and Results Dashboard

## What is a GUI?
A Graphical User Interface lets users interact through buttons, labels, text fields, and windows instead of typing every command into a terminal.

## Main UI components
- **Browse…** opens a file picker.
- **Scan File** calls `analyze_file()` and then `score_file()`.
- **Risk label and progress bar** show the risk level and score.
- **File details** display metadata, detected file signature, and SHA-256.
- **Why this score?** lists each rule that added points and explains it.

## Program flow
1. User chooses a file.
2. User clicks Scan File.
3. `scanner/file_analyzer.py` reads metadata and a small header, and calculates SHA-256. It does not execute the file.
4. `scanner/risk_scorer.py` applies the Day 4 rules.
5. The UI displays the score, classification, and reasons.

## Important concepts
- Tkinter is included with many Python installations and is used to create desktop windows.
- `filedialog.askopenfilename()` opens the file picker.
- `messagebox` displays helpful errors.
- A risk score is a heuristic based on configured rules, not a malware probability.
- LOW means few configured warnings were detected; it does not guarantee safety.

## Demo suggestions
Try `samples/sample.txt`, `samples/invoice.pdf.exe.txt`, and `samples/mismatch.jpg`. These are harmless teaching samples. Compare the risk score and the explanations.
