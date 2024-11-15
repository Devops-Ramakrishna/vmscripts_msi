#!/bin/bash
# audit_config.sh
# CIS_Linux_2.0.0 - 4.1.19
# Define the path to the rules file
rules_file="/etc/audit/rules.d/99-finalize.rules"

# Check if the rules file exists; if not, create it
if [ ! -f "$rules_file" ]; then
    sudo touch "$rules_file"
fi

# Append the line -e 2 to the end of the file if it doesn't already exist
if ! grep -q "^\\-e 2" "$rules_file"; then
    echo "-e 2" | sudo tee -a "$rules_file" > /dev/null
fi

# Reboot the system to apply changes
echo "The line '-e 2' has been added to $rules_file."

# Reload the auditd service to apply changes
sudo augenrules --load

# Remove deny files if they exist
# cron.sh
# CIS_Linux_2.0.0 - 5.1.8
if [ -f /etc/cron.deny ]; then
    sudo rm /etc/cron.deny
    echo "/etc/cron.deny removed."
else
    echo "/etc/cron.deny does not exist."
fi

if [ -f /etc/at.deny ]; then
    sudo rm /etc/at.deny
    echo "/etc/at.deny removed."
else
    echo "/etc/at.deny does not exist."
fi

# Create allow files
if [ ! -f /etc/cron.allow ]; then
    sudo touch /etc/cron.allow
    echo "/etc/cron.allow created."
fi

if [ ! -f /etc/at.allow ]; then
    sudo touch /etc/at.allow
    echo "/etc/at.allow created."
fi

# Set permissions: 600 (read and write for owner only)
sudo chmod 600 /etc/cron.allow
sudo chmod 600 /etc/at.allow

# Set ownership to root:root
sudo chown root:root /etc/cron.allow
sudo chown root:root /etc/at.allow

# Confirm changes
# date_and_time.sh
# CIS_Linux_2.0.0 - 4.1.5
echo "Permissions and ownership set for /etc/cron.allow and /etc/at.allow."
ls -l /etc/cron.allow /etc/at.allow

# Define the audit rules file path
audit_rules_file="/etc/audit/rules.d/audit.rules"

# Backup the original audit.rules file if it exists
if [ -f "$audit_rules_file" ]; then
    sudo cp "$audit_rules_file" "$audit_rules_file.bak"
    echo "Backup of $audit_rules_file created."
else
    sudo touch "$audit_rules_file"
    echo "Created new audit rules file: $audit_rules_file."
fi

# Define the audit rules to be added
rules=(
    "-a always,exit -F arch=b64 -S adjtimex -S settimeofday -k time-change"
    "-a always,exit -F arch=b32 -S adjtimex -S settimeofday -S stime -k time-change"
    "-a always,exit -F arch=b64 -S clock_settime -k time-change"
    "-a always,exit -F arch=b32 -S clock_settime -k time-change"
    "-w /etc/localtime -p wa -k time-change"
)

# Add each rule to the audit rules file if it doesn't already exist
for rule in "${rules[@]}"; do
    if ! grep -qFx "$rule" "$audit_rules_file"; then
        echo "$rule" | sudo tee -a "$audit_rules_file" > /dev/null
        echo "Added rule: $rule"
    else
        echo "Rule already exists: $rule"
    fi
done

# Reload the auditd service to apply changes
sudo augenrules --load

echo "Audit rules have been updated and auditd service restarted."

# Define the audit rules file path
# file_deletion.sh
# CIS_Linux_2.0.0 - 4.1.15
audit_rules_file="/etc/audit/rules.d/audit.rules"

# Backup the original audit.rules file if it exists
if [ -f "$audit_rules_file" ]; then
    sudo cp "$audit_rules_file" "$audit_rules_file.bak"
    echo "Backup of $audit_rules_file created."
else
    sudo touch "$audit_rules_file"
    echo "Created new audit rules file: $audit_rules_file."
fi

# Define the audit rules to be added
rules=(
    "-a always,exit -F arch=b64 -S unlink -S unlinkat -S rename -S renameat -F auid>=500 -F auid!=4294967295 -k delete"
    "-a always,exit -F arch=b32 -S unlink -S unlinkat -S rename -S renameat -F auid>=500 -F auid!=4294967295 -k delete"
)

# Add each rule to the audit rules file if it doesn't already exist
for rule in "${rules[@]}"; do
    if ! grep -qFx "$rule" "$audit_rules_file"; then
        echo "$rule" | sudo tee -a "$audit_rules_file" > /dev/null
        echo "Added rule: $rule"
    else
        echo "Rule already exists: $rule"
    fi
done

# Reload the auditd service to apply changes
sudo augenrules --load

echo "Audit rules have been updated and auditd service restarted."

# Define the audit rules to be added or updated
# file_system_mount.sh
# CIS_Linux_2.0.0 - 4.1.14
rules=(
    "-a always,exit -F arch=b64 -S mount -F auid>=1000 -F auid!=4294967295 -k mounts"
    "-a always,exit -F arch=b32 -S mount -F auid>=1000 -F auid!=4294967295 -k mounts"
)

# Path to the audit rules file
audit_rules_file="/etc/audit/rules.d/audit.rules"

# Create or clear the audit rules file if it doesn't exist
if [ ! -f "$audit_rules_file" ]; then
    sudo touch "$audit_rules_file"
fi

# Add each rule to the audit rules file if it doesn't already exist
for rule in "${rules[@]}"; do
    # Check if the rule already exists in the file
    if ! grep -qFx "$rule" "$audit_rules_file"; then
        echo "$rule" | sudo tee --append "$audit_rules_file" > /dev/null
    fi
done

# Reload the auditd service to apply changes
sudo augenrules --load

echo "Audit rules have been updated in $audit_rules_file."

# Define the sysctl configuration file path
# ICMP_redirects_arenotaccepted.sh
# CIS_Linux_2.0.0 - 3.2.3
sysctl_conf_file="/etc/sysctl.conf"

# Backup the original sysctl.conf file if it exists
if [ -f "$sysctl_conf_file" ]; then
    sudo cp "$sysctl_conf_file" "$sysctl_conf_file.bak"
    echo "Backup of $sysctl_conf_file created."
else
    sudo touch "$sysctl_conf_file"
    echo "Created new sysctl.conf file."
fi

# Define the parameters to be added
parameters=(
    "net.ipv4.conf.all.secure_redirects = 0"
    "net.ipv4.conf.default.secure_redirects = 0"
)

# Add each parameter to the sysctl configuration file if it doesn't already exist
for param in "${parameters[@]}"; do
    # Use double quotes around $param to preserve spaces and check for exact match
    if ! grep -qFx "$param" "$sysctl_conf_file"; then
        echo "$param" | sudo tee -a "$sysctl_conf_file" > /dev/null
        echo "Added: $param"
    else
        echo "Parameter already exists: $param"
    fi
done

# Apply the changes immediately
sudo sysctl -w net.ipv4.conf.all.secure_redirects=0
sudo sysctl -w net.ipv4.conf.default.secure_redirects=0

# Flush routing cache (this command does not persist)
sudo sysctl -w net.ipv4.route.flush=1

echo "Sysctl parameters have been updated and applied."

# Define the sysctl configuration file path
# ICMP_redirects.sh
# CIS_Linux_2.0.0 - 3.2.2
sysctl_conf_file="/etc/sysctl.conf"

# Backup the original sysctl.conf file if it exists
if [ -f "$sysctl_conf_file" ]; then
    sudo cp "$sysctl_conf_file" "$sysctl_conf_file.bak"
    echo "Backup of $sysctl_conf_file created."
else
    sudo touch "$sysctl_conf_file"
    echo "Created new sysctl.conf file."
fi

# Define the parameters to be added
parameters=(
    "net.ipv4.conf.all.accept_redirects = 0"
    "net.ipv4.conf.default.accept_redirects = 0"
    "net.ipv6.conf.all.accept_redirects = 0"
    "net.ipv6.conf.default.accept_redirects = 0"
)

# Add each parameter to the sysctl configuration file if it doesn't already exist
for param in "${parameters[@]}"; do
    # Use double quotes around $param to preserve spaces and check for exact match
    if ! grep -qFx "$param" "$sysctl_conf_file"; then
        echo "$param" | sudo tee -a "$sysctl_conf_file" > /dev/null
        echo "Added: $param"
    else
        echo "Parameter already exists: $param"
    fi
done

# Apply the changes immediately
sudo sysctl -w net.ipv4.conf.all.accept_redirects=0
sudo sysctl -w net.ipv4.conf.default.accept_redirects=0
sudo sysctl -w net.ipv6.conf.all.accept_redirects=0
sudo sysctl -w net.ipv6.conf.default.accept_redirects=0

# Flush routing cache (this command does not persist)
sudo sysctl -w net.ipv4.route.flush=1
sudo sysctl -w net.ipv6.route.flush=1

echo "Sysctl parameters have been updated and applied."

# Define the sysctl configuration file path
# ICMP.sh
# CIS_Linux_2.0.0 - 3.2.2
sysctl_conf_file="/etc/sysctl.conf"

# Backup the original sysctl.conf file if it exists
if [ -f "$sysctl_conf_file" ]; then
    sudo cp "$sysctl_conf_file" "$sysctl_conf_file.bak"
    echo "Backup of $sysctl_conf_file created."
else
    sudo touch "$sysctl_conf_file"
fi

# Define the parameters to be added
parameters=(
    "net.ipv4.conf.all.secure_redirects = 0"
    "net.ipv4.conf.default.secure_redirects = 0"
)

# Add each parameter to the sysctl configuration file if it doesn't already exist
for param in "${parameters[@]}"; do
    # Use double quotes around $param to preserve spaces and check for exact match
    if ! grep -qFx "$param" "$sysctl_conf_file"; then
        echo "$param" | sudo tee -a "$sysctl_conf_file" > /dev/null
        echo "Added: $param"
    else
        echo "Parameter already exists: $param"
    fi
done

# Apply the changes immediately
sudo sysctl -w net.ipv4.conf.all.secure_redirects=0
sudo sysctl -w net.ipv4.conf.default.secure_redirects=0

# Flush routing cache (this command does not persist)
sudo sysctl -w net.ipv4.route.flush=1

echo "Sysctl parameters have been updated and applied."

# Define the useradd defaults file path
# INACTIVE_30.sh 
# CIS_Linux_2.0.0 - 5.4.1.4
useradd_defaults_file="/etc/default/useradd"

# Backup the original useradd defaults file if it exists
if [ -f "$useradd_defaults_file" ]; then
    sudo cp "$useradd_defaults_file" "$useradd_defaults_file.bak"
    echo "Backup of $useradd_defaults_file created."
else
    echo "$useradd_defaults_file does not exist."
    exit 1
fi

# Check if the INACTIVE line exists and update it
if grep -q "^INACTIVE=" "$useradd_defaults_file"; then
    # Update the INACTIVE line to INACTIVE=30
    sudo sed -i 's/^INACTIVE=-1/INACTIVE=30/' "$useradd_defaults_file"
    echo "Updated INACTIVE from -1 to 30 in $useradd_defaults_file."
else
    echo "INACTIVE line not found. Adding it."
    echo "INACTIVE=30" | sudo tee -a "$useradd_defaults_file" > /dev/null
    echo "Added INACTIVE=30 to $useradd_defaults_file."
fi

echo "Operation completed."

# Define the audit rules to be added or updated
# kernel.sh
# CIS_Linux_2.0.0 - 4.1.18
# 
rules=(
    "-w /sbin/insmod -p x -k modules"
    "-w /sbin/rmmod -p x -k modules"
    "-w /sbin/modprobe -p x -k modules"
    "-a always,exit -F arch=b64 -S init_module -S delete_module -k modules"
)

# Path to the audit rules file
audit_rules_file="/etc/audit/rules.d/audit.rules"

# Create or clear the audit rules file if it doesn't exist
if [ ! -f "$audit_rules_file" ]; then
    sudo touch "$audit_rules_file"
fi

# Add each rule to the audit rules file if it doesn't already exist
for rule in "${rules[@]}"; do
    # Check if the rule already exists in the file
    if ! grep -qFx "$rule" "$audit_rules_file"; then
        echo "$rule" | sudo tee --append "$audit_rules_file" > /dev/null
    fi
done

# Reload the auditd service to apply changes
sudo augenrules --load

echo "Audit rules have been updated in $audit_rules_file."

# Define the audit rules file path
# login_and_logout_events.sh
# CIS_Linux_2.0.0 - 4.1.9
audit_rules_file="/etc/audit/rules.d/audit.rules"

# Backup the original audit.rules file if it exists
if [ -f "$audit_rules_file" ]; then
    sudo cp "$audit_rules_file" "$audit_rules_file.bak"
    echo "Backup of $audit_rules_file created."
else
    sudo touch "$audit_rules_file"
    echo "Created new audit rules file: $audit_rules_file."
fi

# Define the audit rules to be added
rules=(
    "-w /var/log/faillog -p wa -k logins"
    "-w /var/log/lastlog -p wa -k logins"
    "-w /var/log/tallylog -p wa -k logins"
)

# Add each rule to the audit rules file if it doesn't already exist
for rule in "${rules[@]}"; do
    if ! grep -qFx "$rule" "$audit_rules_file"; then
        echo "$rule" | sudo tee -a "$audit_rules_file" > /dev/null
        echo "Added rule: $rule"
    else
        echo "Rule already exists: $rule"
    fi
done

# Reload the auditd service to apply changes
sudo augenrules --load

echo "Audit rules have been updated and auditd service restarted."

# Define the audit rules file path
# modify_ug.sh
# CIS_Linux_2.0.0 - 4.1.6
audit_rules_file="/etc/audit/rules.d/audit.rules"

# Backup the original audit.rules file if it exists
if [ -f "$audit_rules_file" ]; then
    sudo cp "$audit_rules_file" "$audit_rules_file.bak"
    echo "Backup of $audit_rules_file created."
else
    sudo touch "$audit_rules_file"
    echo "Created new audit rules file: $audit_rules_file."
fi

# Define the audit rules to be added
rules=(
    "-w /etc/group -p wa -k identity"
    "-w /etc/passwd -p wa -k identity"
    "-w /etc/gshadow -p wa -k identity"
    "-w /etc/shadow -p wa -k identity"
    "-w /etc/security/opasswd -p wa -k identity"
)

# Add each rule to the audit rules file if it doesn't already exist
for rule in "${rules[@]}"; do
    if ! grep -qFx "$rule" "$audit_rules_file"; then
        echo "$rule" | sudo tee -a "$audit_rules_file" > /dev/null
        echo "Added rule: $rule"
    else
        echo "Rule already exists: $rule"
    fi
done

# Reload the auditd service to apply changes
sudo augenrules --load

echo "Audit rules have been updated and auditd service restarted."

# Define the audit rules file path
# network_environment.sh
# CIS_Linux_2.0.0 - 4.1.7
audit_rules_file="/etc/audit/rules.d/audit.rules"

# Backup the original audit.rules file if it exists
if [ -f "$audit_rules_file" ]; then
    sudo cp "$audit_rules_file" "$audit_rules_file.bak"
    echo "Backup of $audit_rules_file created."
else
    sudo touch "$audit_rules_file"
    echo "Created new audit rules file: $audit_rules_file."
fi

# Define the audit rules to be added
rules=(
    "-a always,exit -F arch=b64 -S sethostname -S setdomainname -k system-locale"
    "-a always,exit -F arch=b32 -S sethostname -S setdomainname -k system-locale"
    "-w /etc/issue -p wa -k system-locale"
    "-w /etc/issue.net -p wa -k system-locale"
    "-w /etc/hosts -p wa -k system-locale"
    "-w /etc/sysconfig/network -p wa -k system-locale"
)

# Add each rule to the audit rules file if it doesn't already exist
for rule in "${rules[@]}"; do
    if ! grep -qFx "$rule" "$audit_rules_file"; then
        echo "$rule" | sudo tee -a "$audit_rules_file" > /dev/null
        echo "Added rule: $rule"
    else
        echo "Rule already exists: $rule"
    fi
done

# Reload the auditd service to apply changes
sudo augenrules --load

echo "Audit rules have been updated and auditd service restarted."

# Define the sysctl configuration file path
# packet_redirect.sh
# CIS_Linux_2.0.0 - 3.1.2
sysctl_conf_file="/etc/sysctl.conf"

# Backup the original sysctl.conf file if it exists
if [ -f "$sysctl_conf_file" ]; then
    sudo cp "$sysctl_conf_file" "$sysctl_conf_file.bak"
    echo "Backup of $sysctl_conf_file created."
else
    sudo touch "$sysctl_conf_file"
    echo "Created new sysctl.conf file."
fi

# Define the parameters to be added
parameters=(
    "net.ipv4.conf.all.send_redirects = 0"
    "net.ipv4.conf.default.send_redirects = 0"
)

# Add each parameter to the sysctl configuration file if it doesn't already exist
for param in "${parameters[@]}"; do
    # Use double quotes around $param to preserve spaces and check for exact match
    if ! grep -qFx "$param" "$sysctl_conf_file"; then
        echo "$param" | sudo tee -a "$sysctl_conf_file" > /dev/null
        echo "Added: $param"
    else
        echo "Parameter already exists: $param"
    fi
done

# Apply the changes immediately
sudo sysctl -w net.ipv4.conf.all.send_redirects=0
sudo sysctl -w net.ipv4.conf.default.send_redirects=0

# Flush routing cache (this command does not persist)
sudo sysctl -w net.ipv4.route.flush=1

echo "Sysctl parameters have been updated and applied."

# Define the login.defs file path
# PASS_MIN_DAYS.sh
# CIS_Linux_2.0.0 - 5.4.1.2
login_defs_file="/etc/login.defs"

# Backup the original login.defs file if it exists
if [ -f "$login_defs_file" ]; then
    sudo cp "$login_defs_file" "$login_defs_file.bak"
    echo "Backup of $login_defs_file created."
else
    echo "$login_defs_file does not exist."
    exit 1
fi

# Set PASS_MIN_DAYS to 7
if grep -q "^PASS_MIN_DAYS" "$login_defs_file"; then
    # If the line exists, update it
    sudo sed -i 's/^PASS_MIN_DAYS.*/PASS_MIN_DAYS 7/' "$login_defs_file"
    echo "Updated PASS_MIN_DAYS to 7."
else
    # If the line does not exist, add it
    echo "PASS_MIN_DAYS 7" | sudo tee -a "$login_defs_file" > /dev/null
    echo "Added PASS_MIN_DAYS with value 7."
fi

# Confirm the change
echo "Current setting for PASS_MIN_DAYS:"
grep "^PASS_MIN_DAYS" "$login_defs_file"

# Define the login.defs file path
# password_expiration_365.sh
# CIS_Linux_2.0.0 - 5.4.1.1
login_defs_file="/etc/login.defs"

# Backup the original login.defs file if it exists
if [ -f "$login_defs_file" ]; then
    sudo cp "$login_defs_file" "$login_defs_file.bak"
    echo "Backup of $login_defs_file created."
else
    echo "$login_defs_file does not exist."
    exit 1
fi

# Set PASS_MAX_DAYS to 365
if grep -q "^PASS_MAX_DAYS" "$login_defs_file"; then
    # If the line exists, update it
    sudo sed -i 's/^PASS_MAX_DAYS.*/PASS_MAX_DAYS 365/' "$login_defs_file"
    echo "Updated PASS_MAX_DAYS to 365."
else
    # If the line does not exist, add it
    echo "PASS_MAX_DAYS 365" | sudo tee -a "$login_defs_file" > /dev/null
    echo "Added PASS_MAX_DAYS with value 365."
fi

# Confirm the change
echo "Current setting for PASS_MAX_DAYS:"
grep "^PASS_MAX_DAYS" "$login_defs_file"

# Define the cron directories
# permission_cron.sh
# CIS_Linux_2.0.0 - 5.1.4, 5.1.5, 5.1.6, 5.1.7
cron_dirs=(
    "/etc/cron.hourly"
    "/etc/cron.daily"
    "/etc/cron.weekly"
    "/etc/cron.monthly"
    "/etc/cron.d"
)

# Loop through each directory and set ownership and permissions
for dir in "${cron_dirs[@]}"; do
    # Check if the directory exists
    if [ -d "$dir" ]; then
        # Set ownership to root:root
        sudo chown root:root "$dir"
        echo "Ownership of $dir set to root:root."

        # Set permissions to 700 (drwx------)
        sudo chmod 700 "$dir"
        echo "Permissions for $dir set to 700."
    else
        echo "Directory $dir does not exist."
    fi
done

# Verify changes
echo "Current ownership and permissions:"
for dir in "${cron_dirs[@]}"; do
    if [ -d "$dir" ]; then
        stat "$dir"
    fi
done

# Define the audit rules file path
# permission_modification.sh
# CIS_Linux_2.0.0 - 4.1.11
audit_rules_file="/etc/audit/rules.d/audit.rules"

# Backup the original audit.rules file if it exists
if [ -f "$audit_rules_file" ]; then
    sudo cp "$audit_rules_file" "$audit_rules_file.bak"
    echo "Backup of $audit_rules_file created."
else
    sudo touch "$audit_rules_file"
    echo "Created new audit rules file: $audit_rules_file."
fi

# Define the audit rules to be added
rules=(
    "-a always,exit -F arch=b64 -S chmod -S fchmod -S fchmodat -F auid>=500 -F auid!=4294967295 -k perm_mod"
    "-a always,exit -F arch=b32 -S chmod -S fchmod -S fchmodat -F auid>=500 -F auid!=4294967295 -k perm_mod"
    "-a always,exit -F arch=b64 -S chown -S fchown -S fchownat -S lchown -F auid>=500 -F auid!=4294967295 -k perm_mod"
    "-a always,exit -F arch=b32 -S chown -S fchown -S fchownat -S lchown -F auid>=500 -F auid!=4294967295 -k perm_mod"
    "-a always,exit -F arch=b64 -S setxattr -S lsetxattr -S fsetxattr -S removexattr -S lremovexattr -S fremovexattr -F auid>=500 -F auid!=4294967295 -k perm_mod"
    "-a always,exit -F arch=b32 -S setxattr -S lsetxattr -S fsetxattr -S removexattr -S lremovexattr -S fremovexattr -F auid>=500 -F auid!=4294967295 -k perm_mod"
)

# Add each rule to the audit rules file if it doesn't already exist
for rule in "${rules[@]}"; do
    if ! grep -qFx "$rule" "$audit_rules_file"; then
        echo "$rule" | sudo tee -a "$audit_rules_file" > /dev/null
        echo "Added rule: $rule"
    else
        echo "Rule already exists: $rule"
    fi
done

# Reload the auditd service to apply changes
sudo augenrules --load
echo "Audit rules have been updated and auditd service restarted."

# Define the crontab file path
# permissions_crontab.sh
# CIS_Linux_2.0.0 - 5.1.2
crontab_file="/etc/crontab"

# Set ownership to root:root
sudo chown root:root "$crontab_file"
echo "Ownership of $crontab_file set to root:root."

# Set permissions to 600 (read and write for owner only)
sudo chmod 600 "$crontab_file"
echo "Permissions for $crontab_file set to 600."

# Verify changes
echo "Current ownership and permissions:"
ls -l "$crontab_file"

# permissions_on_alllog.sh
sudo find /var/log -type f -exec chmod g-wx,o-rwx "{}" + -o -type d -exec chmod g-wx,o-rwx "{}" +

# Remediation is applicable only in certain platforms
# permit_root_login.sh
# CIS_Linux_2.0.0 - 5.2.10
if [ ! -f /.dockerenv ] && [ ! -f /run/.containerenv ]; then

if [ -e "/etc/ssh/sshd_config" ] ; then

    LC_ALL=C sed -i "/^\s*PermitRootLogin\s\+/Id" "/etc/ssh/sshd_config"
else
    touch "/etc/ssh/sshd_config"
fi
# make sure file has newline at the end
sed -i -e '$a\' "/etc/ssh/sshd_config"

cp "/etc/ssh/sshd_config" "/etc/ssh/sshd_config.bak"
# Insert at the beginning of the file
printf '%s\n' "PermitRootLogin no" > "/etc/ssh/sshd_config"
cat "/etc/ssh/sshd_config.bak" >> "/etc/ssh/sshd_config"
# Clean up after ourselves.
rm "/etc/ssh/sshd_config.bak"

else
    >&2 echo 'Remediation is not applicable, nothing was done'
fi

# Define the sysctl configuration file path
# reverse_path_filtering.sh 
# CIS_Linux_2.0.0 - 3.2.7
sysctl_conf_file="/etc/sysctl.conf"

# Backup the original sysctl.conf file if it exists
if [ -f "$sysctl_conf_file" ]; then
    sudo cp "$sysctl_conf_file" "$sysctl_conf_file.bak"
else
    sudo touch "$sysctl_conf_file"
fi

# Define the parameters to be added
parameters=(
    "net.ipv4.conf.all.rp_filter = 1"
    "net.ipv4.conf.default.rp_filter = 1"
)

# Add each parameter to the sysctl configuration file if it doesn't already exist
for param in "${parameters[@]}"; do
    # Use double quotes around $param to preserve spaces and check for exact match
    if ! grep -qFx "$param" "$sysctl_conf_file"; then
        echo "$param" | sudo tee -a "$sysctl_conf_file" > /dev/null
    fi
done

# Apply the changes immediately
sudo sysctl -w net.ipv4.conf.all.rp_filter=1
sudo sysctl -w net.ipv4.conf.default.rp_filter=1

# Flush routing cache (this command does not persist)
sudo sysctl -w net.ipv4.route.flush=1

echo "Sysctl parameters have been updated and applied."

# Define the sysctl configuration file path
# routed_packets.sh 
# CIS_Linux_2.0.0 - 3.2.1
sysctl_conf_file="/etc/sysctl.conf"

# Backup the original sysctl.conf file if it exists
if [ -f "$sysctl_conf_file" ]; then
    sudo cp "$sysctl_conf_file" "$sysctl_conf_file.bak"
else
    sudo touch "$sysctl_conf_file"
fi

# Define the parameters to be added
parameters=(
    "net.ipv4.conf.all.accept_source_route = 0"
    "net.ipv4.conf.default.accept_source_route = 0"
    "net.ipv6.conf.all.accept_source_route = 0"
    "net.ipv6.conf.default.accept_source_route = 0"
)

# Add each parameter to the sysctl configuration file if it doesn't already exist
for param in "${parameters[@]}"; do
    # Use double quotes around $param to preserve spaces and check for exact match
    if ! grep -qFx "$param" "$sysctl_conf_file"; then
        echo "$param" | sudo tee -a "$sysctl_conf_file" > /dev/null
    fi
done

# Apply the changes immediately
sudo sysctl -w net.ipv4.conf.all.accept_source_route=0
sudo sysctl -w net.ipv4.conf.default.accept_source_route=0
sudo sysctl -w net.ipv6.conf.all.accept_source_route=0
sudo sysctl -w net.ipv6.conf.default.accept_source_route=0

# Flush routing cache (this command does not persist)
sudo sysctl -w net.ipv4.route.flush=1
sudo sysctl -w net.ipv6.route.flush=1

echo "Sysctl parameters have been updated and applied."

# Define the audit rules file path
# session_initiation.sh
# CIS_Linux_2.0.0 - 4.1.10
audit_rules_file="/etc/audit/rules.d/audit.rules"

# Backup the original audit.rules file if it exists
if [ -f "$audit_rules_file" ]; then
    sudo cp "$audit_rules_file" "$audit_rules_file.bak"
    echo "Backup of $audit_rules_file created."
else
    sudo touch "$audit_rules_file"
    echo "Created new audit rules file: $audit_rules_file."
fi

# Define the audit rules to be added
rules=(
    "-w /var/run/utmp -p wa -k session"
    "-w /var/log/wtmp -p wa -k logins"
    "-w /var/log/btmp -p wa -k logins"
)

# Add each rule to the audit rules file if it doesn't already exist
for rule in "${rules[@]}"; do
    if ! grep -qFx "$rule" "$audit_rules_file"; then
        echo "$rule" | sudo tee -a "$audit_rules_file" > /dev/null
        echo "Added rule: $rule"
    else
        echo "Rule already exists: $rule"
    fi
done

# Reload the auditd service to apply changes
sudo augenrules --load
echo "Audit rules have been updated and auditd service restarted."

# Define the SSH configuration file path
# ssh_X11.sh
# CIS_Linux_2.0.0 - 5.2.6
sshd_config_file="/etc/ssh/sshd_config"

# Backup the original sshd_config file if it exists
if [ -f "$sshd_config_file" ]; then
    sudo cp "$sshd_config_file" "$sshd_config_file.bak"
    echo "Backup of $sshd_config_file created."
else
    echo "$sshd_config_file does not exist."
    exit 1
fi

# Update X11Forwarding setting to no
if grep -q "^X11Forwarding" "$sshd_config_file"; then
    sudo sed -i 's/^X11Forwarding yes/X11Forwarding no/' "$sshd_config_file"
    echo "Updated X11Forwarding from yes to no."
else
    echo "X11Forwarding line not found. Adding it as 'X11Forwarding no'."
    echo "X11Forwarding no" | sudo tee -a "$sshd_config_file" > /dev/null
fi

# Restart SSH service to apply changes
sudo systemctl restart sshd

echo "SSH service restarted. X11 forwarding is now disabled."

# Define the sysctl configuration file 
# suspicious_packets.sh
# CIS_Linux_2.0.0 - 3.2.4
sysctl_conf_file="/etc/sysctl.conf"

# Backup the original sysctl.conf file if it exists
if [ -f "$sysctl_conf_file" ]; then
    sudo cp "$sysctl_conf_file" "$sysctl_conf_file.bak"
else
    sudo touch "$sysctl_conf_file"
fi

# Define the parameters to be added
parameters=(
    "net.ipv4.conf.all.log_martians = 1"
    "net.ipv4.conf.default.log_martians = 1"
)

# Add each parameter to the sysctl configuration file if it doesn't already exist
for param in "${parameters[@]}"; do
    # Use double quotes around $param to preserve spaces and check for exact match
    if ! grep -qFx "$param" "$sysctl_conf_file"; then
        echo "$param" | sudo tee -a "$sysctl_conf_file" > /dev/null
    fi
done

# Apply the changes immediately
sudo sysctl -w net.ipv4.conf.all.log_martians=1
sudo sysctl -w net.ipv4.conf.default.log_martians=1

# Flush routing cache (this command does not persist)
sudo sysctl -w net.ipv4.route.flush=1

echo "Sysctl parameters have been updated and applied."

# Define the path to the audit.rules file
# system_administration.sh
# CIS_Linux_2.0.0 - 4.1.16
audit_rules_file="/etc/audit/audit.rules"

# Backup the original audit.rules file if it exists
if [ -f "$audit_rules_file" ]; then
    sudo cp "$audit_rules_file" "$audit_rules_file.bak"
fi

# Create or clear the audit.rules file if it doesn't exist
sudo touch "$audit_rules_file"

# Define the rules to be added
rules=(
    "-w /etc/sudoers -p wa -k scope"
    "-w /etc/sudoers.d -p wa -k scope"
)

# Add each rule to the audit.rules file if it doesn't already exist
for rule in "${rules[@]}"; do
    if ! grep -qFx "$rule" "$audit_rules_file"; then
        echo "$rule" | sudo tee -a "$audit_rules_file" > /dev/null
    fi
done

# Reload the auditd service to apply changes (optional)
sudo augenrules --load

echo "Audit rules have been updated in $audit_rules_file."

# Define the audit rules file path
# system_Mandatory.sh
# CIS_Linux_2.0.0 - 4.1.8
audit_rules_file="/etc/audit/rules.d/audit.rules"

# Backup the original audit.rules file if it exists
if [ -f "$audit_rules_file" ]; then
    sudo cp "$audit_rules_file" "$audit_rules_file.bak"
    echo "Backup of $audit_rules_file created."
else
    sudo touch "$audit_rules_file"
    echo "Created new audit rules file: $audit_rules_file."
fi

# Define the audit rules for SELinux
selinux_rules=(
    "-w /etc/selinux/ -p wa -k MAC-policy"
    "-w /usr/share/selinux/ -p wa -k MAC-policy"
)

# Define the audit rules for AppArmor
apparmor_rules=(
    "-w /etc/apparmor/ -p wa -k MAC-policy"
    "-w /etc/apparmor.d/ -p wa -k MAC-policy"
)

# Add SELinux rules to the audit rules file if they don't already exist
for rule in "${selinux_rules[@]}"; do
    if ! grep -qFx "$rule" "$audit_rules_file"; then
        echo "$rule" | sudo tee -a "$audit_rules_file" > /dev/null
        echo "Added SELinux rule: $rule"
    else
        echo "SELinux rule already exists: $rule"
    fi
done

# Add AppArmor rules to the audit rules file if they don't already exist
for rule in "${apparmor_rules[@]}"; do
    if ! grep -qFx "$rule" "$audit_rules_file"; then
        echo "$rule" | sudo tee -a "$audit_rules_file" > /dev/null
        echo "Added AppArmor rule: $rule"
    else
        echo "AppArmor rule already exists: $rule"
    fi
done

# Reload the auditd service to apply changes
sudo augenrules --load
echo "Audit rules have been updated and auditd service restarted."

# Define the audit rules file path
# unsuccessful_unauthorized.sh
# CIS_Linux_2.0.0 - 4.1.12
audit_rules_file="/etc/audit/rules.d/audit.rules"

# Backup the original audit.rules file if it exists
if [ -f "$audit_rules_file" ]; then
    sudo cp "$audit_rules_file" "$audit_rules_file.bak"
    echo "Backup of $audit_rules_file created."
else
    sudo touch "$audit_rules_file"
    echo "Created new audit rules file: $audit_rules_file."
fi

# Define the audit rules to be added
rules=(
    "-a always,exit -F arch=b64 -S creat -S open -S openat -S truncate -S ftruncate -F exit=-EACCES -F auid>=500 -F auid!=4294967295 -k access"
    "-a always,exit -F arch=b32 -S creat -S open -S openat -S truncate -S ftruncate -F exit=-EACCES -F auid>=500 -F auid!=4294967295 -k access"
    "-a always,exit -F arch=b64 -S creat -S open -S openat -S truncate -S ftruncate -F exit=-EPERM -F auid>=500 -F auid!=4294967295 -k access"
    "-a always,exit -F arch=b32 -S creat -S open -S openat -S truncate -S ftruncate -F exit=-EPERM -F auid>=500 -F auid!=4294967295 -k access"
)

# Add each rule to the audit rules file if it doesn't already exist
for rule in "${rules[@]}"; do
    if ! grep -qFx "$rule" "$audit_rules_file"; then
        echo "$rule" | sudo tee -a "$audit_rules_file" > /dev/null
        echo "Added rule: $rule"
    else
        echo "Rule already exists: $rule"
    fi
done

# Reload the auditd service to apply changes
sudo augenrules --load
echo "Audit rules have been updated and auditd service restarted."