import streamlit as st
import pandas as pd
from datetime import datetime
import os
from pathlib import Path
from file_monitor import FileMonitor
from hash_utils import calculate_file_hash
from utils import initialize_session_state, get_status_color, save_scan_report

# Initialize session state
initialize_session_state()

# Page configuration
st.set_page_config(
    page_title="File Change Monitor",
    page_icon="🔍",
    layout="wide"
)

# Title and description
st.title("File Change Monitoring Tool")
st.markdown("Monitor files, folders, and drives for changes using hash comparison")

# Sidebar
with st.sidebar:
    st.header("Settings")

    # Monitor type selection
    monitor_type = st.selectbox(
        "What to Monitor",
        ["Files", "Folder", "Drive"],
        help="Select what you want to monitor"
    )

    # Path input based on monitor type
    if monitor_type == "Files":
        uploaded_files = st.file_uploader(
            "Upload files",
            accept_multiple_files=True,
            help="Select files to monitor for changes"
        )
    else:
        path_to_monitor = st.text_input(
            f"Enter {monitor_type} path",
            help=f"Enter the path to the {monitor_type.lower()} you want to monitor"
        )
        recursive = st.checkbox(
            "Monitor recursively",
            value=True,
            help="Monitor all subfolders and files"
        )

    # Hash algorithm selection
    hash_algorithm = st.selectbox(
        "Hash Algorithm",
        ["sha256", "md5", "sha1"],
        help="Select the hash algorithm to use for file comparison"
    )

    # Monitoring duration
    duration_type = st.radio(
        "Monitoring Duration",
        ["Until Stopped", "Time Interval"],
        help="Choose how long to monitor"
    )

    if duration_type == "Time Interval":
        interval = st.slider(
            "Check Interval (seconds)",
            min_value=1,
            max_value=300,
            value=60,
            help="How often to check for file changes"
        )

    # Initial scan option
    if st.button("Perform Initial Scan"):
        st.session_state.initial_scan = True
        st.session_state.monitoring = False

    # Start/Stop monitoring
    if st.button("Start Monitoring" if not st.session_state.monitoring else "Stop Monitoring"):
        st.session_state.monitoring = not st.session_state.monitoring
        st.session_state.initial_scan = False

# Main content area
col1, col2 = st.columns([2, 1])

with col1:
    # Process paths to monitor
    if monitor_type == "Files" and uploaded_files:
        for uploaded_file in uploaded_files:
            file_path = uploaded_file.name
            if file_path not in st.session_state.monitored_files:
                try:
                    with open(file_path, "wb") as f:
                        f.write(uploaded_file.getvalue())
                    initial_hash = calculate_file_hash(file_path, hash_algorithm)
                    st.session_state.monitored_files[file_path] = {
                        "hash": initial_hash,
                        "status": "Unchanged",
                        "last_checked": datetime.now()
                    }
                except Exception as e:
                    st.error(f"Error processing file {file_path}: {str(e)}")

    elif (monitor_type in ["Folder", "Drive"]) and path_to_monitor:
        if os.path.exists(path_to_monitor):
            paths_to_scan = []
            if recursive:
                for root, _, files in os.walk(path_to_monitor):
                    paths_to_scan.extend([os.path.join(root, f) for f in files])
            else:
                paths_to_scan = [
                    os.path.join(path_to_monitor, f) for f in os.listdir(path_to_monitor)
                    if os.path.isfile(os.path.join(path_to_monitor, f))
                ]

            for file_path in paths_to_scan:
                if file_path not in st.session_state.monitored_files:
                    try:
                        initial_hash = calculate_file_hash(file_path, hash_algorithm)
                        st.session_state.monitored_files[file_path] = {
                            "hash": initial_hash,
                            "status": "Unchanged",
                            "last_checked": datetime.now()
                        }
                    except Exception as e:
                        st.error(f"Error processing file {file_path}: {str(e)}")
        else:
            st.error(f"Invalid {monitor_type.lower()} path")

with col2:
    # Display monitoring status
    st.subheader("Monitoring Status")
    status_text = "Active" if st.session_state.monitoring else "Inactive"
    st.markdown(f"**Status:** {status_text}")
    if duration_type == "Time Interval":
        st.markdown(f"**Interval:** {interval} seconds")
    else:
        st.markdown("**Duration:** Until Stopped")
    st.markdown(f"**Algorithm:** {hash_algorithm}")

    # Export scan results
    if st.button("Export Current Scan"):
        report_path = save_scan_report(st.session_state.monitored_files, st.session_state.change_log)
        st.success(f"Scan report saved to: {report_path}")

# Display monitored files
st.subheader("Monitored Files")
if st.session_state.monitored_files:
    data = []
    for path, info in st.session_state.monitored_files.items():
        data.append({
            "File Path": path,
            "Current Hash": info["hash"],
            "Status": info["status"],
            "Last Checked": info["last_checked"].strftime("%Y-%m-%d %H:%M:%S")
        })

    df = pd.DataFrame(data)
    st.dataframe(
        df.style.apply(lambda x: [f"background-color: {get_status_color(val)}" 
                               for val in x.Status], subset=["Status"]),
        use_container_width=True
    )
else:
    st.info("No files are currently being monitored. Select files or a path to begin monitoring.")

# Change log
st.subheader("Change Log")
if st.session_state.change_log:
    log_df = pd.DataFrame(st.session_state.change_log)
    st.dataframe(log_df, use_container_width=True)
else:
    st.info("No changes detected yet.")

# Monitor files if active
if st.session_state.monitoring or st.session_state.initial_scan:
    monitor = FileMonitor(st.session_state.monitored_files, hash_algorithm)
    changes = monitor.check_files()

    if changes:
        for change in changes:
            st.session_state.change_log.append({
                "Timestamp": datetime.now(),
                "File": change["file"],
                "Action": change["action"],
                "Previous Hash": change["old_hash"],
                "New Hash": change["new_hash"]
            })

        # Update session state
        st.session_state.monitored_files = monitor.files
        st.experimental_rerun()

    # If this was an initial scan, stop after one check
    if st.session_state.initial_scan:
        st.session_state.initial_scan = False
    elif duration_type == "Time Interval":
        time.sleep(interval)
    else:
        time.sleep(1)  # Prevent too frequent updates for continuous monitoring
