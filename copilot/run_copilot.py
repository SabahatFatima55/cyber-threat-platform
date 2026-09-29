"""
Terminal interface for the Security Copilot.
Run: python copilot/run_copilot.py
"""

import os
import sys
import pandas as pd

sys.path.append(os.path.join(os.path.dirname(__file__), ".."))
from copilot.security_copilot import SecurityCopilot

PROCESSED_PATH = os.path.join(os.path.dirname(__file__), "..", "outputs", "processed_logs.csv")


def main():
    if not os.path.exists(PROCESSED_PATH):
        print("No processed data found. Run `python main.py` first.")
        return

    df = pd.read_csv(PROCESSED_PATH)
    copilot = SecurityCopilot(df)

    print("=" * 60)
    print("AI Security Copilot (terminal mode) - type 'exit' to quit")
    print("=" * 60)
    print("Try: 'What are the top attacks?', 'Which users were affected?',")
    print("     'Show highest risk flows', 'Recommend next actions'\n")

    while True:
        q = input("You: ").strip()
        if q.lower() in ("exit", "quit"):
            break
        if not q:
            continue
        print(f"Copilot: {copilot.answer(q)}\n")


if __name__ == "__main__":
    main()
