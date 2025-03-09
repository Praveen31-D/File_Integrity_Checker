import os
import sys
import pandas as pd
from datetime import datetime
import platform

def get_app_data_dir():
    """Get platform-specific application data directory"""
    system = platform.system().lower()
    if system == 'windows':
        base_dir = os.getenv('APPDATA')
    elif system == 'darwin':
        base_dir = os.path.expanduser('~/Library/Application Support')
    else:
        base_dir = os.path.expanduser('~/.local/share')

    app_dir = os.path.join(base_dir, 'FileMonitor')
    os.makedirs(app_dir, exist_ok=True)
    return app_dir

def get_status_color(status):
    """Return color code for file status."""
    status_colors = {
        'Unchanged': '#f0f2f6',
        'Modified': '#ffeb3b',
        'Deleted': '#ff4444',
        'Added': '#4caf50'
    }
    return status_colors.get(status, '#f0f2f6')

def save_scan_report(monitored_files, change_log):
    """Save current scan results to a file."""
    # Use platform-specific app data directory
    reports_dir = os.path.join(get_app_data_dir(), 'reports')
    os.makedirs(reports_dir, exist_ok=True)

    # Generate timestamp for filename
    timestamp = datetime.now().strftime('%Y%m%d_%H%M%S')
    report_path = os.path.normpath(os.path.join(reports_dir, f'scan_report_{timestamp}.csv'))

    try:
        # Prepare data for export
        data = []
        for path, info in monitored_files.items():
            data.append({
                'File Path': path,
                'Current Hash': info['hash'],
                'Status': info['status'],
                'Last Checked': info['last_checked'].strftime('%Y-%m-%d %H:%M:%S')
            })

        # Save to CSV
        df = pd.DataFrame(data)
        df.to_csv(report_path, index=False)

        # If there's a change log, save it as well
        if change_log:
            log_path = os.path.normpath(os.path.join(
                reports_dir, f'change_log_{timestamp}.csv'))
            log_df = pd.DataFrame(change_log)
            log_df.to_csv(log_path, index=False)

        return report_path
    except Exception as e:
        raise Exception(f"Error saving report: {str(e)}")