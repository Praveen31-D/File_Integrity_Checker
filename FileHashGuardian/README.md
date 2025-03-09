# FileHashGuardian

## Overview
FileHashGuardian is a robust file integrity monitoring tool that helps you track and verify the integrity of your files through cryptographic hash calculations. The application allows you to monitor directories, calculate file hashes using various algorithms, detect changes in files, and generate reports.

## Features
- **Multiple Hash Algorithms**: Support for MD5, SHA1, and SHA256 hash calculations
- **Real-time File Monitoring**: Monitor directories for file changes and detect modifications
- **User-friendly GUI**: Easy-to-use desktop interface built with PyQt5
- **Detailed Reporting**: Export hash information to CSV or JSON formats
- **File Comparison**: Compare files based on their hash values to detect alterations
- **Directory Scanning**: Recursively scan directories and calculate hashes for all files
- **Saved Configurations**: Save monitored directories and their baseline hashes for future comparisons

## Installation

### Prerequisites
- Python 3.6 or higher
- PyQt5
- Other dependencies as listed in requirements.txt

### Setup
1. Clone the repository:
```
git clone https://github.com/yourusername/FileHashGuardian.git
cd FileHashGuardian
```

2. Create a virtual environment (optional but recommended):
```
python -m venv venv
source venv/bin/activate  # On Windows: venv\Scripts\activate
```

3. Install the required packages:
```
pip install -r requirements.txt
```

## Usage

### Launch the Application
```
python main.py
```

### Basic Workflow
1. **Select Directory**: Choose a directory to monitor or scan for file hashes
2. **Calculate Hashes**: Calculate hashes for all files in the selected directory
3. **Set Baseline**: Save the current hash values as a baseline for future comparison
4. **Monitor Files**: Enable real-time monitoring to detect changes to files
5. **Export Reports**: Generate and export reports in CSV or JSON format

### Hash Calculation
- Select the desired hash algorithm (MD5, SHA1, SHA256)
- Choose a file or directory to calculate hashes
- View the calculated hash results in the application

### File Monitoring
- Add directories to the monitoring list
- Start the monitoring service to detect changes in real-time
- Receive notifications when file changes are detected

## Project Structure
- `main.py`: Entry point of the application
- `desktop_app.py`: Main PyQt5 desktop application implementation
- `file_monitor.py`: File monitoring and change detection functionality
- `hash_utils.py`: Hash calculation utilities for different algorithms
- `utils.py`: General utility functions for file operations and reporting

## Contributing
Contributions are welcome! Please feel free to submit a Pull Request.

## License
This project is licensed under the MIT License - see the LICENSE file for details.

