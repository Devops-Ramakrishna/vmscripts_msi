#!/bin/bash

# 1. Extract the .tar.gz file from specified path
tar_file="/root/scripts.tar.gz"
extract_path="/etc/containers/systemd"

tar -xvzf "$tar_file" -C "$extract_path"

# 2. Copy the .container files to /etc/containers/systemd path
container_files_path="$extract_path/container_files"
systemd_path="/etc/containers/systemd"

cp "$container_files_path"/*.container "$systemd_path"

# 3. Reload daemon
systemctl daemon-reload

# 4. Start the services
services=("service1" "service2")

for service in "${services[@]}"; do
    systemctl start "$service"
done
