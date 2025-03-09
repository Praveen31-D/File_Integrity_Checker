import os
from datetime import datetime
from hash_utils import calculate_file_hash

class FileMonitor:
    def __init__(self, files, hash_algorithm):
        self.files = files
        self.hash_algorithm = hash_algorithm
        
    def check_files(self):
        """Check monitored files for changes."""
        changes = []
        
        for file_path in list(self.files.keys()):
            try:
                if not os.path.exists(file_path):
                    # File was deleted
                    changes.append({
                        "file": file_path,
                        "action": "Deleted",
                        "old_hash": self.files[file_path]["hash"],
                        "new_hash": None
                    })
                    self.files[file_path]["status"] = "Deleted"
                    continue
                
                current_hash = calculate_file_hash(file_path, self.hash_algorithm)
                
                if current_hash != self.files[file_path]["hash"]:
                    # File was modified
                    changes.append({
                        "file": file_path,
                        "action": "Modified",
                        "old_hash": self.files[file_path]["hash"],
                        "new_hash": current_hash
                    })
                    self.files[file_path]["hash"] = current_hash
                    self.files[file_path]["status"] = "Modified"
                
                self.files[file_path]["last_checked"] = datetime.now()
                
            except Exception as e:
                print(f"Error checking file {file_path}: {str(e)}")
        
        return changes
