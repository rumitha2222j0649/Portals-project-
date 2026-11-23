"""
main.py - Entry point for Portal Scanner.
Launches the Tkinter GUI dashboard.
"""

import sys
import tkinter as tk
from tkinter import messagebox

from gui import PortalScannerGUI


def main():
    """Main application runner."""
    try:
        root = tk.Tk()
    except Exception as e:
        print(f"Error initializing GUI window: {e}", file=sys.stderr)
        sys.exit(1)

    app = PortalScannerGUI(root)
    root.mainloop()


if __name__ == "__main__":
    main()

