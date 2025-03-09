import sys
import tkinter as tk
from tkinter import ttk, filedialog, messagebox
from desktop_app import FileMonitorApp

def main():
    """Launch the desktop file monitoring application."""
    root = tk.Tk()
    app = FileMonitorApp(root)
    root.mainloop()

if __name__ == "__main__":
    main()