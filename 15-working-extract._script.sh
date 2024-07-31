#!/bin/bash

# Set the current directory and log file
current_dir=$PWD
logfile="$current_dir/latest_script.log"

# Function to print messages to the log file with timestamp
Print2Log() {
    local msg="$1"
    echo "[`date +%Y-%m-%d_%H:%M:%S:%3N`] ${msg}" >> "$logfile"
}

# Define variables
tar_file="/root/containers.tar.gz"
extract_path="/root"
service="my_service_name"

# Check if the tar file exists
if [[ ! -f "$tar_file" ]]; then
    Print2Log "Error: Tar file $tar_file does not exist." >> "$logfile"
    exit 1
fi

# 1. Extract the .tar.gz file
if tar -xvzf "$tar_file" -C "$extract_path"; then
    Print2Log "Successfully extracted $tar_file to $extract_path." >> "$logfile"
else
    Print2Log "Error: Failed to extract $tar_file." >> "$logfile"
    exit 1
fi

# 2. Copy the .container files to /etc/containers/systemd path
container_files_path="$extract_path/containers"
systemd_path="/etc/containers/systemd"

# Check if the container files directory exists
if [[ ! -d "$container_files_path" ]]; then
    Print2Log "Error: Container files directory $container_files_path does not exist." >> "$logfile"
    exit 1
fi

# Check if .container files already exist in the systemd path
if ls "$systemd_path"/*.container 1> /dev/null 2>&1; then
    Print2Log "Error: .container files already exist in $systemd_path. Exiting."
    exit 1
fi

if cp "$container_files_path"/*.container "$systemd_path"; then
    Print2Log "Successfully copied .container files to $systemd_path." >> "$logfile"
else
    Print2Log "Error: Failed to copy .container files." >> "$logfile"
    exit 1
fi

# 3. Reload daemon
if systemctl daemon-reload; then
    Print2Log "Successfully reloaded the systemd daemon." >> "$logfile"
else
    Print2Log "Error: Failed to reload the systemd daemon." >> "$logfile"
    exit 1
fi

# 4. Start the service
if systemctl start "$service"; then
    Print2Log "Successfully started $service." >> "$logfile"
else
    Print2Log "Error: Failed to start $service." >> "$logfile"
    exit 1
fi

Print2Log "Script execution completed successfully."
