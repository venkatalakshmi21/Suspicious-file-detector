"""Day 5: Tkinter UI for the Suspicious File Detector.

This tool performs basic static checks. It never executes the selected file.
"""
import tkinter as tk
from tkinter import ttk, filedialog, messagebox
from pathlib import Path
from scanner.file_analyzer import analyze_file
from scanner.risk_scorer import score_file

BG = "#f3f6fb"
NAVY = "#172554"
TEXT = "#1f2937"
MUTED = "#64748b"
RISK_COLORS = {"LOW": "#15803d", "MEDIUM": "#b45309", "HIGH": "#b91c1c"}

class SuspiciousFileDetectorApp(tk.Tk):
    def __init__(self):
        super().__init__()
        self.title("Suspicious File Detector | Day 5")
        self.geometry("900x720")
        self.minsize(760, 620)
        self.configure(bg=BG)
        self.selected_path = tk.StringVar()
        self._build_ui()

    def _build_ui(self):
        header = tk.Frame(self, bg=NAVY, padx=24, pady=20)
        header.pack(fill="x")
        tk.Label(header, text="SUSPICIOUS FILE DETECTOR", bg=NAVY, fg="white",
                 font=("Segoe UI", 20, "bold")).pack(anchor="w")
        tk.Label(header, text="Static file checks • Explainable risk scoring • Day 5 dashboard",
                 bg=NAVY, fg="#cbd5e1", font=("Segoe UI", 10)).pack(anchor="w", pady=(5, 0))

        main = tk.Frame(self, bg=BG, padx=22, pady=18)
        main.pack(fill="both", expand=True)
        tk.Label(main, text="Choose a file to scan", bg=BG, fg=TEXT,
                 font=("Segoe UI", 12, "bold")).pack(anchor="w")
        chooser = tk.Frame(main, bg=BG)
        chooser.pack(fill="x", pady=(8, 14))
        entry = ttk.Entry(chooser, textvariable=self.selected_path)
        entry.pack(side="left", fill="x", expand=True, ipady=7)
        ttk.Button(chooser, text="Browse…", command=self.browse_file).pack(side="left", padx=(8, 0), ipady=3)
        ttk.Button(chooser, text="Scan File", command=self.scan_file).pack(side="left", padx=(8, 0), ipady=3)

        self.result_card = tk.Frame(main, bg="white", padx=18, pady=16,
                                    highlightbackground="#dbe3ef", highlightthickness=1)
        self.result_card.pack(fill="x")
        top = tk.Frame(self.result_card, bg="white")
        top.pack(fill="x")
        tk.Label(top, text="RISK ASSESSMENT", bg="white", fg=MUTED,
                 font=("Segoe UI", 9, "bold")).pack(side="left")
        self.level_label = tk.Label(top, text="NOT SCANNED", bg="#e2e8f0", fg="#334155",
                                     padx=12, pady=5, font=("Segoe UI", 10, "bold"))
        self.level_label.pack(side="right")
        self.score_label = tk.Label(self.result_card, text="— / 100", bg="white", fg=NAVY,
                                    font=("Segoe UI", 25, "bold"))
        self.score_label.pack(anchor="w", pady=(8, 2))
        self.score_bar = ttk.Progressbar(self.result_card, maximum=100, mode="determinate")
        self.score_bar.pack(fill="x", pady=(2, 10))
        self.summary_label = tk.Label(self.result_card, text="Select a file and click Scan File to view results.",
                                      bg="white", fg=TEXT, wraplength=790, justify="left",
                                      font=("Segoe UI", 10))
        self.summary_label.pack(anchor="w")

        details = tk.Frame(main, bg=BG)
        details.pack(fill="both", expand=True, pady=(16, 0))
        tk.Label(details, text="FILE DETAILS", bg=BG, fg=TEXT,
                 font=("Segoe UI", 11, "bold")).pack(anchor="w", pady=(0, 6))
        self.details_text = tk.Text(details, height=8, wrap="word", bg="white", fg=TEXT,
                                    relief="flat", padx=12, pady=10, font=("Consolas", 9),
                                    highlightbackground="#dbe3ef", highlightthickness=1)
        self.details_text.pack(fill="x")
        self.details_text.insert("1.0", "File name, size, extension, signature, and SHA-256 will appear here.")
        self.details_text.configure(state="disabled")

        tk.Label(details, text="WHY THIS SCORE?", bg=BG, fg=TEXT,
                 font=("Segoe UI", 11, "bold")).pack(anchor="w", pady=(14, 6))
        self.reasons_text = tk.Text(details, height=6, wrap="word", bg="white", fg=TEXT,
                                    relief="flat", padx=12, pady=10, font=("Segoe UI", 10),
                                    highlightbackground="#dbe3ef", highlightthickness=1)
        self.reasons_text.pack(fill="both", expand=True)
        self.reasons_text.insert("1.0", "The dashboard will explain each detected indicator and its points.")
        self.reasons_text.configure(state="disabled")

        footer = tk.Label(self, text="Educational heuristic only — a LOW score does not prove a file is safe. Never execute suspicious files to test them.",
                          bg=BG, fg=MUTED, font=("Segoe UI", 9), padx=18, pady=10, wraplength=850)
        footer.pack(fill="x")

    def browse_file(self):
        path = filedialog.askopenfilename(title="Select a file to analyze")
        if path:
            self.selected_path.set(path)

    @staticmethod
    def _set_text(widget, content):
        widget.configure(state="normal")
        widget.delete("1.0", "end")
        widget.insert("1.0", content)
        widget.configure(state="disabled")

    def scan_file(self):
        raw_path = self.selected_path.get().strip().strip('"')
        if not raw_path:
            messagebox.showinfo("Choose a file", "Please browse and select a file first.")
            return
        try:
            analysis = analyze_file(Path(raw_path))
            result = score_file(analysis)
        except (OSError, ValueError, KeyError, TypeError) as exc:
            messagebox.showerror("Scan failed", f"Could not analyze this file.\n\n{exc}")
            return

        level = result["risk_level"]
        self.level_label.configure(text=level + " RISK", bg=RISK_COLORS[level], fg="white")
        self.score_label.configure(text=f"{result['risk_score']} / 100")
        self.score_bar.configure(value=result["risk_score"])
        self.summary_label.configure(text=result["summary"])
        details = (
            f"File name       : {analysis['file_name']}\n"
            f"Path            : {analysis['absolute_path']}\n"
            f"Size            : {analysis['size_bytes']} bytes ({analysis['size_kb']:.2f} KB)\n"
            f"Extension       : {analysis['extension'] or '[none]'}\n"
            f"Category        : {analysis['extension_category']}\n"
            f"Detected format : {analysis['signature_type']}\n"
            f"Signature check : {analysis['signature_match']}\n"
            f"Modified        : {analysis['modified_time']}\n"
            f"SHA-256         : {analysis['sha256']}"
        )
        self._set_text(self.details_text, details)
        if result["reasons"]:
            reasons = "\n\n".join(
                f"+{item['points']} points — {item['explanation']}\nIndicator: {item['indicator']}"
                for item in result["reasons"]
            )
        else:
            reasons = "No configured warning indicators were triggered. This does not prove the file is safe."
        self._set_text(self.reasons_text, reasons)

def main():
    app = SuspiciousFileDetectorApp()
    app.mainloop()

if __name__ == "__main__":
    main()
