#!/bin/bash

# Define variables
tar_file="/root/scripts.tar.gz"
extract_path="/etc/containers/systemd"
service="myservice"

# 1. Extract the .tar.gz file
if tar -xvzf "$tar_file" -C "$extract_path"; then
    echo "Successfully extracted $tar_file to $extract_path."
else
    echo "Error: Failed to extract $tar_file."
    exit 1
fi

# 2. Copy the .container files to /etc/containers/systemd path
container_files_path="$extract_path/container_files"
systemd_path="/etc/containers/systemd"

if cp "$container_files_path"/*.container "$systemd_path"; then
    echo "Successfully copied .container files to $systemd_path."
else
    echo "Error: Failed to copy .container files."
    exit 1
fi

# 3. Reload daemon
if systemctl daemon-reload; then
    echo "Successfully reloaded the systemd daemon."
else
    echo "Error: Failed to reload the systemd daemon."
    exit 1
fi

# 4. Start the service
if systemctl start "$service"; then
    echo "Successfully started $service."
else
    echo "Error: Failed to start $service."
    exit 1
fi

echo "All operations completed successfully."
