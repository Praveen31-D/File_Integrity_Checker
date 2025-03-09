import os
import sys
import tkinter as tk
from tkinter import ttk, filedialog, messagebox
from datetime import datetime
from file_monitor import FileMonitor
from hash_utils import calculate_file_hash
from utils import save_scan_report
import platform

class FileMonitorApp:
    def __init__(self, root):
        self.root = root
        self.root.title("File Change Monitor")
        self.root.geometry("1200x800")

        # Set platform-specific styling
        self.setup_platform_style()

        # Initialize monitoring state
        self.monitored_files = {}
        self.change_log = []
        self.monitoring = False

        # Create main layout
        self.create_gui()

        # Setup monitoring timer
        self.check_files_pending = False
        self.root.after(1000, self.check_files_timer)

    def setup_platform_style(self):
        """Configure platform-specific styling"""
        style = ttk.Style()

        # Set theme based on platform
        if platform.system().lower() == 'windows':
            style.theme_use('vista')
        elif platform.system().lower() == 'darwin':
            style.theme_use('aqua')
        else:
            style.theme_use('clam')

        # Common styling for all platforms
        style.configure("TButton", padding=6)
        style.configure("TLabel", padding=3)
        style.configure("Treeview", rowheight=25)
        style.configure("TFrame", padding=5)

    def create_gui(self):
        # Main container with padding
        main_container = ttk.Frame(self.root, padding="5")
        main_container.pack(fill=tk.BOTH, expand=True)

        # Left panel (controls)
        left_panel = ttk.Frame(main_container)
        left_panel.pack(side=tk.LEFT, fill=tk.Y, padx=5, pady=5)

        # Control section
        controls_frame = ttk.LabelFrame(left_panel, text="Monitor Controls", padding="10")
        controls_frame.pack(fill=tk.X, pady=5)

        # File selection
        ttk.Label(controls_frame, text="Select Type:").pack(anchor=tk.W)
        self.monitor_type = ttk.Combobox(controls_frame, 
                                       values=["Files", "Folder"],
                                       state="readonly")
        self.monitor_type.set("Files")
        self.monitor_type.pack(fill=tk.X, pady=5)

        # Path selection button
        self.select_path_btn = ttk.Button(controls_frame, 
                                        text="Select Path",
                                        command=self.select_path)
        self.select_path_btn.pack(fill=tk.X, pady=5)

        # Options frame
        options_frame = ttk.LabelFrame(left_panel, text="Options", padding="10")
        options_frame.pack(fill=tk.X, pady=5)

        # Recursive option
        self.recursive_var = tk.BooleanVar(value=True)
        ttk.Checkbutton(options_frame, 
                       text="Include Subfolders",
                       variable=self.recursive_var).pack(anchor=tk.W)

        # Hash algorithm
        ttk.Label(options_frame, text="Hash Algorithm:").pack(anchor=tk.W)
        self.hash_algo = ttk.Combobox(options_frame,
                                    values=["sha256", "md5", "sha1"],
                                    state="readonly")
        self.hash_algo.set("sha256")
        self.hash_algo.pack(fill=tk.X, pady=5)

        # Monitoring interval
        interval_frame = ttk.Frame(options_frame)
        interval_frame.pack(fill=tk.X, pady=5)
        ttk.Label(interval_frame, text="Check Every:").pack(side=tk.LEFT)
        self.interval_spin = ttk.Spinbox(interval_frame,
                                       from_=1, to=300,
                                       width=5)
        self.interval_spin.set("60")
        self.interval_spin.pack(side=tk.LEFT, padx=5)
        ttk.Label(interval_frame, text="seconds").pack(side=tk.LEFT)

        # Action buttons frame
        actions_frame = ttk.LabelFrame(left_panel, text="Actions", padding="10")
        actions_frame.pack(fill=tk.X, pady=5)

        self.scan_btn = ttk.Button(actions_frame,
                                 text="Initial Scan",
                                 command=self.perform_initial_scan)
        self.scan_btn.pack(fill=tk.X, pady=2)

        self.monitor_btn = ttk.Button(actions_frame,
                                    text="Start Monitoring",
                                    command=self.toggle_monitoring)
        self.monitor_btn.pack(fill=tk.X, pady=2)

        self.export_btn = ttk.Button(actions_frame,
                                   text="Export Report",
                                   command=self.export_scan)
        self.export_btn.pack(fill=tk.X, pady=2)

        # Right panel (tables)
        right_panel = ttk.Frame(main_container)
        right_panel.pack(side=tk.LEFT, fill=tk.BOTH, expand=True, padx=5)

        # Notebook for tables
        notebook = ttk.Notebook(right_panel)
        notebook.pack(fill=tk.BOTH, expand=True)

        # Files table
        files_frame = ttk.Frame(notebook, padding="5")
        notebook.add(files_frame, text="Monitored Files")

        self.files_table = ttk.Treeview(files_frame,
                                      columns=("path", "hash", "status", "checked"),
                                      show="headings",
                                      selectmode="extended")

        # Configure columns
        self.files_table.heading("path", text="File Path")
        self.files_table.heading("hash", text="Current Hash")
        self.files_table.heading("status", text="Status")
        self.files_table.heading("checked", text="Last Checked")

        # Set column widths
        self.files_table.column("path", width=300)
        self.files_table.column("hash", width=200)
        self.files_table.column("status", width=100)
        self.files_table.column("checked", width=150)

        # Add scrollbar
        files_scroll = ttk.Scrollbar(files_frame,
                                   orient=tk.VERTICAL,
                                   command=self.files_table.yview)
        self.files_table.configure(yscrollcommand=files_scroll.set)

        self.files_table.pack(side=tk.LEFT, fill=tk.BOTH, expand=True)
        files_scroll.pack(side=tk.RIGHT, fill=tk.Y)

        # Change log table
        log_frame = ttk.Frame(notebook, padding="5")
        notebook.add(log_frame, text="Change Log")

        self.log_table = ttk.Treeview(log_frame,
                                    columns=("time", "file", "action", "old_hash", "new_hash"),
                                    show="headings",
                                    selectmode="extended")

        # Configure columns
        self.log_table.heading("time", text="Time")
        self.log_table.heading("file", text="File")
        self.log_table.heading("action", text="Action")
        self.log_table.heading("old_hash", text="Previous Hash")
        self.log_table.heading("new_hash", text="New Hash")

        # Set column widths
        self.log_table.column("time", width=150)
        self.log_table.column("file", width=300)
        self.log_table.column("action", width=100)
        self.log_table.column("old_hash", width=200)
        self.log_table.column("new_hash", width=200)

        # Add scrollbar
        log_scroll = ttk.Scrollbar(log_frame,
                                 orient=tk.VERTICAL,
                                 command=self.log_table.yview)
        self.log_table.configure(yscrollcommand=log_scroll.set)

        self.log_table.pack(side=tk.LEFT, fill=tk.BOTH, expand=True)
        log_scroll.pack(side=tk.RIGHT, fill=tk.Y)

        # Status bar
        self.status_var = tk.StringVar()
        self.status_var.set("Ready")
        status_bar = ttk.Label(main_container,
                             textvariable=self.status_var,
                             relief=tk.SUNKEN,
                             padding="2")
        status_bar.pack(side=tk.BOTTOM, fill=tk.X)

    def select_path(self):
        """Handle file/folder selection"""
        try:
            if self.monitor_type.get() == "Files":
                files = filedialog.askopenfilenames(
                    title="Select Files to Monitor",
                    filetypes=[("All Files", "*.*")]
                )
                if files:
                    for file_path in files:
                        self.add_file_to_monitor(os.path.normpath(file_path))
            else:
                folder = filedialog.askdirectory(
                    title="Select Folder to Monitor"
                )
                if folder:
                    self.process_directory(os.path.normpath(folder))
        except Exception as e:
            messagebox.showerror("Error", f"Error selecting path: {str(e)}")

    def add_file_to_monitor(self, file_path):
        """Add a file to monitoring"""
        try:
            if file_path not in self.monitored_files:
                initial_hash = calculate_file_hash(file_path, self.hash_algo.get())
                self.monitored_files[file_path] = {
                    "hash": initial_hash,
                    "status": "Unchanged",
                    "last_checked": datetime.now()
                }
                self.update_files_table()
                self.status_var.set(f"Added: {os.path.basename(file_path)}")
        except PermissionError:
            messagebox.showwarning(
                "Access Denied",
                f"Cannot access file: {file_path}\nPlease check permissions."
            )
        except Exception as e:
            messagebox.showwarning(
                "Error",
                f"Error processing file {file_path}: {str(e)}"
            )

    def process_directory(self, path):
        """Process directory recursively if selected"""
        if not os.path.exists(path):
            messagebox.showerror("Error", f"Directory not found: {path}")
            return

        try:
            if self.recursive_var.get():
                for root, _, files in os.walk(path):
                    for file in files:
                        self.add_file_to_monitor(
                            os.path.normpath(os.path.join(root, file))
                        )
            else:
                for file in os.listdir(path):
                    file_path = os.path.normpath(os.path.join(path, file))
                    if os.path.isfile(file_path):
                        self.add_file_to_monitor(file_path)
        except PermissionError:
            messagebox.showerror(
                "Access Denied",
                f"Cannot access some files in: {path}\nPlease check permissions."
            )
        except Exception as e:
            messagebox.showerror(
                "Error",
                f"Error processing directory: {str(e)}"
            )

    def update_files_table(self):
        """Update the files table display"""
        try:
            self.files_table.delete(*self.files_table.get_children())
            for path, info in self.monitored_files.items():
                self.files_table.insert("", tk.END, values=(
                    path,
                    info["hash"],
                    info["status"],
                    info["last_checked"].strftime("%Y-%m-%d %H:%M:%S")
                ))
        except Exception as e:
            messagebox.showerror("Error", f"Error updating files table: {str(e)}")

    def update_log_table(self):
        """Update the change log table display"""
        try:
            self.log_table.delete(*self.log_table.get_children())
            for log in self.change_log:
                self.log_table.insert("", 0, values=(  # Insert at top
                    log["Timestamp"].strftime("%Y-%m-%d %H:%M:%S"),
                    log["File"],
                    log["Action"],
                    log["Previous Hash"],
                    log["New Hash"]
                ))
        except Exception as e:
            messagebox.showerror("Error", f"Error updating log table: {str(e)}")

    def perform_initial_scan(self):
        """Perform initial scan of monitored files"""
        if not self.monitored_files:
            messagebox.showwarning("Warning", "No files are being monitored")
            return

        try:
            self.status_var.set("Performing initial scan...")
            monitor = FileMonitor(self.monitored_files, self.hash_algo.get())
            changes = monitor.check_files()
            self.process_changes(changes)
            self.status_var.set("Initial scan completed")
            messagebox.showinfo("Scan Complete", "Initial scan completed successfully")
        except Exception as e:
            self.status_var.set("Scan failed")
            messagebox.showerror("Error", f"Error during initial scan: {str(e)}")

    def toggle_monitoring(self):
        """Toggle monitoring state"""
        try:
            if not self.monitoring:
                if not self.monitored_files:
                    messagebox.showwarning("Warning", "No files to monitor")
                    return

                self.monitoring = True
                self.monitor_btn.configure(text="Stop Monitoring")
                self.status_var.set("Monitoring active")
                messagebox.showinfo(
                    "Monitoring Started",
                    "File monitoring has been started"
                )
            else:
                self.monitoring = False
                self.monitor_btn.configure(text="Start Monitoring")
                self.status_var.set("Monitoring stopped")
                messagebox.showinfo(
                    "Monitoring Stopped",
                    "File monitoring has been stopped"
                )
        except Exception as e:
            messagebox.showerror("Error", f"Error toggling monitoring: {str(e)}")

    def check_files_timer(self):
        """Timer callback for periodic file checking"""
        if self.monitoring and not self.check_files_pending:
            self.check_files_pending = True
            try:
                self.check_files()
            finally:
                self.check_files_pending = False

        # Schedule next check
        try:
            interval = int(self.interval_spin.get()) * 1000
        except ValueError:
            interval = 60000  # Default to 60 seconds
        self.root.after(interval, self.check_files_timer)

    def check_files(self):
        """Check monitored files for changes"""
        try:
            if self.monitored_files:
                monitor = FileMonitor(self.monitored_files, self.hash_algo.get())
                changes = monitor.check_files()
                if changes:
                    self.process_changes(changes)
        except Exception as e:
            messagebox.showerror("Error", f"Error checking files: {str(e)}")
            self.toggle_monitoring()  # Stop monitoring on error

    def process_changes(self, changes):
        """Process detected changes"""
        if changes:
            try:
                for change in changes:
                    self.change_log.append({
                        "Timestamp": datetime.now(),
                        "File": change["file"],
                        "Action": change["action"],
                        "Previous Hash": change["old_hash"],
                        "New Hash": change["new_hash"]
                    })
                    self.status_var.set(
                        f"Change detected: {change['action']} - {os.path.basename(change['file'])}"
                    )

                self.update_files_table()
                self.update_log_table()
            except Exception as e:
                messagebox.showerror("Error", f"Error processing changes: {str(e)}")

    def export_scan(self):
        """Export monitoring results"""
        if not self.monitored_files:
            messagebox.showwarning("Warning", "No files are being monitored")
            return

        try:
            save_path = filedialog.asksaveasfilename(
                defaultextension=".csv",
                filetypes=[("CSV Files", "*.csv")],
                title="Save Monitoring Report"
            )

            if save_path:
                self.status_var.set("Exporting report...")
                report_path = save_scan_report(self.monitored_files, self.change_log)
                self.status_var.set("Report exported successfully")
                messagebox.showinfo(
                    "Export Complete",
                    f"Report saved to:\n{report_path}"
                )
        except Exception as e:
            self.status_var.set("Export failed")
            messagebox.showerror("Error", f"Failed to export report: {str(e)}")

def main():
    """Launch the desktop file monitoring application"""
    root = tk.Tk()
    app = FileMonitorApp(root)

    # Center window on screen
    root.update_idletasks()
    width = root.winfo_width()
    height = root.winfo_height()
    x = (root.winfo_screenwidth() // 2) - (width // 2)
    y = (root.winfo_screenheight() // 2) - (height // 2)
    root.geometry(f'{width}x{height}+{x}+{y}')

    root.mainloop()

if __name__ == '__main__':
    main()