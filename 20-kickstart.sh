#!/bin/bash
# Remediation is applicable only in certain platforms
# stig scripts
# V-230244
sudo sed -i 's/^#ClientAliveCountMax .*/ClientAliveCountMax 1/' /etc/ssh/sshd_config
sudo systemctl restart sshd

# Uncomment StrictModes in sshd_config
# V-230288
sudo sed -i 's/^#StrictModes yes/StrictModes yes/' /etc/ssh/sshd_config
sudo systemctl restart sshd

# Uncomment IgnoreUserKnownHosts in sshd_config and set it to yes
# V-230290
sudo sed -i 's/^#IgnoreUserKnownHosts no/IgnoreUserKnownHosts yes/' /etc/ssh/sshd_config
sudo systemctl restart sshd

# Uncomment KerberosAuthentication in sshd_config and set it to no
# V-230291
sudo sed -i 's/^#KerberosAuthentication no/KerberosAuthentication no/' /etc/ssh/sshd_config
sudo systemctl restart sshd

# Remediation is applicable only in certain platforms
# V-230296
sudo sed -i 's/^#*PermitRootLogin.*$/PermitRootLogin no/' /etc/ssh/sshd_config
sudo systemctl restart sshd

# Define the configuration file
# V-230313
LIMITS_FILE="/etc/security/limits.conf"
LIMITS_DIR="/etc/security/limits.d"
CONF_FILE="disable_coredumps.conf"

# Check if limits.conf exists
if [ ! -f "$LIMITS_FILE" ]; then
    echo "Configuration file $LIMITS_FILE does not exist."
    exit 1
fi

# Add the line to limits.conf if it doesn't already exist
if ! grep -q '^* hard core 0' "$LIMITS_FILE"; then
    echo "* hard core 0" | sudo tee -a "$LIMITS_FILE" > /dev/null
    echo "Added '* hard core 0' to $LIMITS_FILE."
else
    echo "'* hard core 0' already exists in $LIMITS_FILE."
fi

# Alternatively, create a new .conf file in limits.d if preferred
if [ ! -f "$LIMITS_DIR/$CONF_FILE" ]; then
    echo "* hard core 0" | sudo tee "$LIMITS_DIR/$CONF_FILE" > /dev/null
    echo "Created $LIMITS_DIR/$CONF_FILE with '* hard core 0'."
else
    echo "'$CONF_FILE' already exists in $LIMITS_DIR."
fi

# Reload the auditd service to apply changes using augenrules
sudo augenrules --load

echo "Core dumps have been disabled for all users."

# Remediation is applicable only in certain platforms
# V-230314
sudo sed -i 's/^#*Storage=.*/Storage=none/' /etc/systemd/coredump.conf

# Remediation is applicable only in certain platforms
# V-230315
sudo sed -i 's/^#*ProcessSizeMax=.*/ProcessSizeMax=0/' /etc/systemd/coredump.conf

# Remediation is applicable only in certain platforms
# V-230330
sudo sed -i 's/^#PermitUserEnvironment no/PermitUserEnvironment no/' /etc/ssh/sshd_config
sudo systemctl restart sshd

# Uncomment deny and fail_interval in faillock.conf and set their values
# V-230333_V-230345
sudo sed -i 's/^# deny = 3/deny = 3/' /etc/security/faillock.conf
sudo sed -i 's/^# fail_interval = 900/fail_interval = 900/' /etc/security/faillock.conf
sudo sed -i 's/^# unlock_time = 600/unlock_time = 0/' /etc/security/faillock.conf
sudo sed -i 's/^# silent/silent/' /etc/security/faillock.conf
sudo sed -i 's/^# audit/audit/' /etc/security/faillock.conf
sudo sed -i 's/^# even_deny_root/even_deny_root/' /etc/security/faillock.conf

# Define the limits.conf file path
# V-230346
limits_conf_file="/etc/security/limits.conf"
new_line="* hard maxlogins 10"

# Backup the original limits.conf file if it exists
if [ -f "$limits_conf_file" ]; then
    sudo cp "$limits_conf_file" "$limits_conf_file.bak"
    echo "Backup of $limits_conf_file created."
else
    echo "$limits_conf_file does not exist."
    exit 1
fi

# Check if the line already exists in the file
if grep -q "^$new_line" "$limits_conf_file"; then
    echo "The line '$new_line' already exists in $limits_conf_file."
else
    # Prepend the new line to the limits.conf file
    echo "$new_line" | sudo cat - "$limits_conf_file" > /tmp/limits.conf && sudo mv /tmp/limits.conf "$limits_conf_file"
    echo "Added '$new_line' to the top of $limits_conf_file."
fi

echo "Changes have been applied."

# Define the shells configuration file path
# V-230350
shells_file="/etc/shells"

# Backup the original shells file if it exists
if [ -f "$shells_file" ]; then
    sudo cp "$shells_file" "$shells_file.bak"
    echo "Backup of $shells_file created."
else
    echo "$shells_file does not exist."
    exit 1
fi

# Check if tmux is present in the shells file and remove it
if grep -q "tmux" "$shells_file"; then
    sudo sed -i '/tmux/d' "$shells_file"
    echo "Removed instances of 'tmux' from $shells_file."
else
    echo "'tmux' not found in $shells_file."
fi

echo "Operation completed."

# Uncomment ucredit in pwquality.conf and set it to -1
# V-230357_V-230363
sudo sed -i 's/^# ucredit = 0/ucredit = -1/' /etc/security/pwquality.conf
sudo sed -i 's/^# lcredit = 0/lcredit = -1/' /etc/security/pwquality.conf
sudo sed -i 's/^# dcredit = 0/dcredit = -1/' /etc/security/pwquality.conf
sudo sed -i 's/^# maxclassrepeat = 0/maxclassrepeat = 4/' /etc/security/pwquality.conf
sudo sed -i 's/^# maxrepeat = 0/maxrepeat = 3/' /etc/security/pwquality.conf
sudo sed -i 's/^# minclass = 0/minclass = 4/' /etc/security/pwquality.conf
sudo sed -i 's/^# difok = 1/difok = 8/' /etc/security/pwquality.conf

# Change PASS_MIN_DAYS from 0 to 1 in login.defs
# V-230365_V-230366
sudo sed -i 's/^PASS_MIN_DAYS\s\+[0-9]\+/PASS_MIN_DAYS   1/' /etc/login.defs
sudo sed -i 's/^PASS_MAX_DAYS\s\+[0-9]\+/PASS_MAX_DAYS   60/' /etc/login.defs

#V-230364
#sudo chage -m 1 cpeinfra
#sudo chage -m 1 root

#V-230367 -- Please find the fix
#sudo chage -M 60 cpeinfra
#sudo chage -M 60 root

# Define the line to add or modify
# V-230368
line="password requisite pam_pwhistory.so use_authtok remember=5 retry=3"

# Check if the line already exists in the file
if grep -q "^password requisite pam_pwhistory.so" /etc/pam.d/password-auth; then
    # If it exists, modify it
    sudo sed -i "s/^password requisite pam_pwhistory.so.*/$line/" /etc/pam.d/password-auth
else
    # If it does not exist, add it to the end of the file
    echo "$line" | sudo tee -a /etc/pam.d/password-auth > /dev/null
fi

# Uncomment minlen in pwquality.conf and set it to 15
# V-230369
sudo sed -i 's/^# minlen = 8/minlen = 15/' /etc/security/pwquality.conf

# Change PASS_MIN_LEN from 5 to 15 in login.defs
# V-230370
sudo sed -i 's/^PASS_MIN_LEN\s\+[0-9]\+/PASS_MIN_LEN    15/' /etc/login.defs

# Uncomment ocredit in pwquality.conf and set it to -1
# V-230375_V-230377
sudo sed -i 's/^# ocredit = 0/ocredit = -1/' /etc/security/pwquality.conf
sudo sed -i 's/^# dictcheck = 1/dictcheck=1/' /etc/security/pwquality.conf

# Define the desired value for FAIL_DELAY
# V-230378
desired_value=4

# Check if FAIL_DELAY is already defined in login.defs
if grep -q '^FAIL_DELAY' /etc/login.defs; then
    # If it exists, update it to the desired value
    sudo sed -i "s/^FAIL_DELAY\s\+[0-9]\+/FAIL_DELAY $desired_value/" /etc/login.defs
else
    # If it does not exist, append it to the end of the file
    echo "FAIL_DELAY $desired_value" | sudo tee -a /etc/login.defs > /dev/null
fi

# Define the PAM configuration file path
# V-230381
pam_postlogin_file="/etc/pam.d/postlogin"
new_line="session required pam_lastlog.so showfailed"

# Backup the original postlogin file if it exists
if [ -f "$pam_postlogin_file" ]; then
    sudo cp "$pam_postlogin_file" "$pam_postlogin_file.bak"
    echo "Backup of $pam_postlogin_file created."
else
    echo "$pam_postlogin_file does not exist."
    exit 1
fi

# Check if the line already exists in the file
if grep -q "^$new_line" "$pam_postlogin_file"; then
    echo "The line '$new_line' already exists in $pam_postlogin_file."
else
    # Prepend the new line to the postlogin file
    echo "$new_line" | sudo cat - "$pam_postlogin_file" > /tmp/postlogin && sudo mv /tmp/postlogin "$pam_postlogin_file"
    echo "Added '$new_line' to the top of $pam_postlogin_file."
fi

echo "Operation completed."

# Uncomment PrintLastLog in sshd_config
# V-230382
sudo sed -i 's/^#PrintLastLog yes/PrintLastLog yes/' /etc/ssh/sshd_config
sudo systemctl restart sshd

# Update UMASK in login.defs to 077
# V-230383
sudo sed -i 's/^UMASK.*$/UMASK 077/' /etc/login.defs

# Define the audit rules to be added or updated
# V-230386
rules=(
    "-a always,exit -F arch=b32 -S execve -C uid!=euid -F euid=0 -k execpriv"
    "-a always,exit -F arch=b64 -S execve -C uid!=euid -F euid=0 -k execpriv"
    "-a always,exit -F arch=b32 -S execve -C gid!=egid -F egid=0 -k execpriv"
    "-a always,exit -F arch=b64 -S execve -C gid!=egid -F egid=0 -k execpriv"
)

# Path to the audit rules file
audit_rules_file="/etc/audit/rules.d/audit.rules"

# Create or clear the audit rules file if it doesn't exist
if [ ! -f "$audit_rules_file" ]; then
    sudo touch "$audit_rules_file"
fi

# Add each rule to the audit rules file if it doesn't already exist
for rule in "${rules[@]}"; do
    if ! grep -qFx "$rule" "$audit_rules_file"; then
        echo "$rule" | sudo tee --append "$audit_rules_file" > /dev/null
    fi
done

# Reload the auditd service to apply changes
sudo augenrules --load

echo "Audit rules have been updated."

# Define the configuration file
# V-230390
CONFIG_FILE="/etc/audit/auditd.conf"

# Check if the configuration file exists
if [ ! -f "$CONFIG_FILE" ]; then
    echo "Configuration file $CONFIG_FILE does not exist."
    exit 1
fi

# Use sed to replace disk_error_action from SUSPEND to HALT
sed -i 's/^disk_error_action = SUSPEND/disk_error_action = HALT/' "$CONFIG_FILE"

# Check if the sed command was successful
if [ $? -eq 0 ]; then
    echo "Successfully changed disk_error_action from SUSPEND to HALT."
else
    echo "Failed to change disk_error_action."
    exit 1
fi

# Reload the auditd service to apply changes
sudo augenrules --load

echo "auditd service restarted."

# Define the configuration file
# V-230392
CONFIG_FILE="/etc/audit/auditd.conf"

# Check if the configuration file exists
if [ ! -f "$CONFIG_FILE" ]; then
    echo "Configuration file $CONFIG_FILE does not exist."
    exit 1
fi

# Use sed to replace disk_full_action from SUSPEND to HALT
sed -i 's/^disk_full_action = SUSPEND/disk_full_action = HALT/' "$CONFIG_FILE"

# Check if the sed command was successful
if [ $? -eq 0 ]; then
    echo "Successfully changed disk_full_action from SUSPEND to HALT."
else
    echo "Failed to change disk_full_action."
    exit 1
fi

# Reload the auditd service to apply changes using augenrules
sudo augenrules --load

echo "Audit configuration updated and service reloaded."

# Define the configuration file
# V-230394
CONFIG_FILE="/etc/audit/auditd.conf"

# Check if the configuration file exists
if [ ! -f "$CONFIG_FILE" ]; then
    echo "Configuration file $CONFIG_FILE does not exist."
    exit 1
fi

# Use sed to replace name_format from NONE to hostname
sed -i 's/^name_format = NONE/name_format = hostname/' "$CONFIG_FILE"

# Check if the sed command was successful
if [ $? -eq 0 ]; then
    echo "Successfully changed name_format from NONE to hostname."
else
    echo "Failed to change name_format."
    exit 1
fi

# Reload the auditd service to apply changes using augenrules
sudo augenrules --load

echo "Audit configuration updated and service reloaded."

# Define the audit rules to be added or updated
# V-230402_to_V-230427
rules=(
    "-e 2"
    "--loginuid-immutable"
    "-w /etc/shadow -p wa -k identity"
    "-w /etc/security/opasswd -p wa -k identity"
    "-w /etc/passwd -p wa -k identity"
    "-w /etc/gshadow -p wa -k identity"
    "-w /etc/group -p wa -k identity"
    "-w /etc/sudoers -p wa -k identity"
    "-w /etc/sudoers.d/ -p wa -k identity"
    "-a always,exit -F path=/usr/bin/su -F perm=x -F auid>=1000 -F auid!=unset -k privileged-priv_change"
    "-a always,exit -F arch=b32 -S setxattr,fsetxattr,lsetxattr,removexattr,fremovexattr,lremovexattr -F auid>=1000 -F auid!=unset -k perm_mod"
    "-a always,exit -F arch=b64 -S setxattr,fsetxattr,lsetxattr,removexattr,fremovexattr,lremovexattr -F auid>=1000 -F auid!=unset -k perm_mod"
    "-a always,exit -F arch=b32 -S setxattr,fsetxattr,lsetxattr,removexattr,fremovexattr,lremovexattr -F auid=0 -k perm_mod"
    "-a always,exit -F arch=b64 -S setxattr,fsetxattr,lsetxattr,removexattr,fremovexattr,lremovexattr -F auid=0 -k perm_mod"
    "-a always,exit -F path=/usr/bin/chage -F perm=x -F auid>=1000 -F auid!=unset -k privileged-chage"
    "-a always,exit -F path=/usr/bin/chcon -F perm=x -F auid>=1000 -F auid!=unset -k perm_mod"
    "-a always,exit -F path=/usr/bin/ssh-agent -F perm=x -F auid>=1000 -F auid!=unset -k privileged-ssh"
    "-a always,exit -F path=/usr/bin/passwd -F perm=x -F auid>=1000 -F auid!=unset -k privileged-passwd"
    "-a always,exit -F path=/usr/bin/mount -F perm=x -F auid>=1000 -F auid!=unset -k privileged-mount"
    "-a always,exit -F path=/usr/bin/umount -F perm=x -F auid>=1000 -F auid!=unset -k privileged-mount"
    "-a always,exit -F arch=b32 -S mount -F auid>=1000 -F auid!=unset -k privileged-mount"
    "-a always,exit -F arch=b64 -S mount -F auid>=1000 -F auid!=unset -k privileged-mount"
    "-a always,exit -F path=/usr/sbin/unix_update -F perm=x -F auid>=1000 -F auid!=unset -k privileged-unix-update"
    "-a always,exit -F path=/usr/sbin/postdrop -F perm=x -F auid>=1000 -F auid!=unset -k privileged-unix-update"
)

# Path to the audit rules file
audit_rules_file="/etc/audit/rules.d/audit.rules"

# Create or clear the audit rules file if it doesn't exist
if [ ! -f "$audit_rules_file" ]; then
    sudo touch "$audit_rules_file"
fi

# Add each rule to the audit rules file if it doesn't already exist
for rule in "${rules[@]}"; do
    if ! grep -qFx "$rule" "$audit_rules_file"; then
        echo "$rule" | sudo tee --append "$audit_rules_file" > /dev/null
    fi
done

# Reload the auditd service to apply changes
sudo augenrules --load

# Define the audit rules to be added or updated
# V-230428_to_V-230467
rules=(
    "-a always,exit -F path=/usr/sbin/postqueue -F perm=x -F auid>=1000 -F auid!=unset -k privileged-unix-update"
    "-a always,exit -F path=/usr/sbin/semanage -F perm=x -F auid>=1000 -F auid!=unset -k privileged-unix-update"
    "-a always,exit -F path=/usr/sbin/setfiles -F perm=x -F auid>=1000 -F auid!=unset -k privileged-unix-update"
    "-a always,exit -F path=/usr/sbin/userhelper -F perm=x -F auid>=1000 -F auid!=unset -k privileged-unix-update"
    "-a always,exit -F path=/usr/sbin/setsebool -F perm=x -F auid>=1000 -F auid!=unset -k privileged-unix-update"
    "-a always,exit -F path=/usr/sbin/unix_chkpwd -F perm=x -F auid>=1000 -F auid!=unset -k privileged-unix-update"
    "-a always,exit -F path=/usr/libexec/openssh/ssh-keysign -F perm=x -F auid>=1000 -F auid!=unset -k privileged-ssh"
    "-a always,exit -F path=/usr/bin/setfacl -F perm=x -F auid>=1000 -F auid!=unset -k perm_mod"
    "-a always,exit -F path=/usr/sbin/pam_timestamp_check -F perm=x -F auid>=1000 -F auid!=unset -k privileged-pam_timestamp_check"
    "-a always,exit -F path=/usr/bin/newgrp -F perm=x -F auid>=1000 -F auid!=unset -k priv_cmd"
    "-a always,exit -F arch=b32 -S init_module,finit_module -F auid>=1000 -F auid!=unset -k module_chng"
    "-a always,exit -F arch=b64 -S init_module,finit_module -F auid>=1000 -F auid!=unset -k module_chng"
    "-a always,exit -F arch=b32 -S rename,unlink,rmdir,renameat,unlinkat -F auid>=1000 -F auid!=unset -k delete"
    "-a always,exit -F arch=b64 -S rename,unlink,rmdir,renameat,unlinkat -F auid>=1000 -F auid!=unset -k delete"
    "-a always,exit -F path=/usr/bin/gpasswd -F perm=x -F auid>=1000 -F auid!=unset -k privileged-gpasswd"
    "-a always,exit -F arch=b32 -S delete_module -F auid>=1000 -F auid!=unset -k module_chng"
    "-a always,exit -F arch=b64 -S delete_module -F auid>=1000 -F auid!=unset -k module_chng"
    "-a always,exit -F path=/usr/bin/crontab -F perm=x -F auid>=1000 -F auid!=unset -k privileged-crontab"
    "-a always,exit -F path=/usr/bin/chsh -F perm=x -F auid>=1000 -F auid!=unset -k priv_cmd"
    "-a always,exit -F arch=b32 -S truncate,ftruncate,creat,open,openat,open_by_handle_at  -F exit=-EPERM  -F auid>=1000  -F auid!=unset  -k perm_access"
    "-a always,exit  -F arch=b64  -S truncate,ftruncate,creat,open,openat,open_by_handle_at  -F exit=-EPERM  -F auid>=1000  -F auid!=unset  -k perm_access"
    "-a always,exit  -F arch=b32  -S truncate,ftruncate,creat,open,openat,open_by_handle_at  -F exit=-EACCES  -F auid>=1000  -F auid!=unset  -k perm_access"
    "-a always,exit  -F arch=b64  -S truncate,ftruncate,creat,open,openat,open_by_handle_at  -F exit=-EACCES  -F auid>=1000  -F auid!=unset  -k perm_access"
    "-a always,exit  -F arch=b32  -S chown,fchown,fchownat,lchown  -F auid>=1000  -F auid!=unset  -k perm_mod"
    "-a always,exit  -F arch=b64  -S chown,fchown,fchownat,lchown  -F auid>=1000  -F auid!=unset  -k perm_mod"
    "-a always,exit  -F arch=b32  -S chmod,fchmod,fchmodat  -F auid>=1000  -F auid!=unset  -k perm_mod"
    "-a always,exit  -F arch=b64  -S chmod,fchmod,fchmodat  -F auid>=1000  -F auid!=unset  -k perm_mod"
    "-a always,exit  -F path=/usr/bin/sudo  -F perm=x  -F auid>=1000  -F auid!=unset  -k priv_cmd"
    "-a always,exit  -F path=/usr/sbin/usermod  -F perm=x  -F auid>=1000  -F auid!=unset  -k privileged-usermod"
    "-a always,exit  -F path=/usr/bin/chacl  -F perm=x  -F auid>=1000  -F auid!=unset  -k perm_mod"
    "-a always,exit  -F path=/usr/bin/kmod   -F perm=x  -F auid>=1000  -F auid!=unset  -F modules"
    "-w /var/log/lastlog -p wa -k logins"
)

# Path to the audit rules file
audit_rules_file="/etc/audit/rules.d/audit.rules"

# Create or clear the audit rules file if it doesn't exist
if [ ! -f "$audit_rules_file" ]; then
    sudo touch "$audit_rules_file"
fi

# Add each rule to the audit rules file if it doesn't already exist
for rule in "${rules[@]}"; do
    if ! grep -qFx "$rule" "$audit_rules_file"; then
        echo "$rule" | sudo tee --append "$audit_rules_file" > /dev/null
    fi
done

# Reload the auditd service to apply changes
sudo augenrules --load

# Define the audit rules file
# V-230465
AUDIT_RULES_FILE="/etc/audit/rules.d/audit.rules"

# Check if the audit rules file exists
if [ ! -f "$AUDIT_RULES_FILE" ]; then
    echo "Audit rules file $AUDIT_RULES_FILE does not exist."
    exit 1
fi

# Add the audit rule if it doesn't already exist
if ! grep -q '^-a always,exit -F path=/usr/bin/kmod' "$AUDIT_RULES_FILE"; then
    echo "-a always,exit -F path=/usr/bin/kmod -F perm=x -F auid>=1000 -F auid!=unset -k modules" | sudo tee -a "$AUDIT_RULES_FILE" > /dev/null
    echo "Added audit rule for kmod execution."
else
    echo "Audit rule for kmod execution already exists."
fi

# Reload audit rules using augenrules
sudo augenrules --load

echo "Audit configuration for kmod is complete."

# Path to the auditd.conf file
# V-230483
auditd_config_file="/etc/audit/auditd.conf"

# Backup the original auditd.conf file
sudo cp "$auditd_config_file" "$auditd_config_file.bak"

# Uncomment and set space_left to 25%
sudo sed -i 's/^space_left\s*=\s*[0-9]\+/space_left = 25%/' "$auditd_config_file"

# Reload the auditd service to apply changes
sudo augenrules --load
echo "Updated space_left to 25% in $auditd_config_file."

# Define the chrony configuration file path
# V-230485_V-230486
chrony_conf_file="/etc/chrony.conf"
new_lines="port 0\ncmdport 0"

# Backup the original chrony.conf file if it exists
if [ -f "$chrony_conf_file" ]; then
    sudo cp "$chrony_conf_file" "$chrony_conf_file.bak"
    echo "Backup of $chrony_conf_file created."
else
    echo "$chrony_conf_file does not exist."
    exit 1
fi

# Check if the lines already exist in the file
if grep -q "^port 0" "$chrony_conf_file" && grep -q "^cmdport 0" "$chrony_conf_file"; then
    echo "The lines 'port 0' and 'cmdport 0' already exist in $chrony_conf_file."
else
    # Prepend the new lines to the chrony.conf file
    {
        echo -e "$new_lines"
        cat "$chrony_conf_file"
    } | sudo tee "$chrony_conf_file" > /dev/null
    echo "Added 'port 0' and 'cmdport 0' to the top of $chrony_conf_file."
fi

# Restart the chronyd service to apply changes
sudo systemctl restart chronyd

echo "Chronyd service restarted. Configuration changes applied."

# Path to the sshd_config file
# V-230527
sshd_config_file="/etc/ssh/sshd_config"

# Check if the sshd_config file exists
if [ ! -f "$sshd_config_file" ]; then
    echo "Error: $sshd_config_file does not exist."
    exit 1
fi

# Backup the original sshd_config file
sudo cp "$sshd_config_file" "$sshd_config_file.bak"

# Uncomment and update RekeyLimit
sudo sed -i 's/^#RekeyLimit.*$/RekeyLimit 1G 1h/' "$sshd_config_file"

# Reload the SSH daemon to apply changes
sudo systemctl reload sshd

echo "RekeyLimit has been set to 1G 1h in $sshd_config_file."

# Path to the sshd_config file
# V-230555
sshd_config_file="/etc/ssh/sshd_config"

# Backup the original sshd_config file
sudo cp "$sshd_config_file" "$sshd_config_file.bak"

# Uncomment and set X11Forwarding to no
sudo sed -i 's/^#\s*X11Forwarding no/X11Forwarding no/' "$sshd_config_file"

# Reload the SSH daemon to apply changes
sudo systemctl reload sshd

echo "Uncommented and set X11Forwarding to no in $sshd_config_file."

# Path to the sshd_config file
# V-230556
sshd_config_file="/etc/ssh/sshd_config"

# Uncomment and set X11UseLocalhost to yes
sudo sed -i 's/^#\s*X11UseLocalhost.*/X11UseLocalhost yes/' "$sshd_config_file"

# Reload the SSH daemon to apply changes
sudo systemctl reload sshd

echo "Uncommented and set X11UseLocalhost to yes in $sshd_config_file."

# Remediation is applicable only in certain platforms
# V-244540_V-244541
if [ ! -f /.dockerenv ] && [ ! -f /run/.containerenv ]; then

if [ -f /usr/bin/authselect ]; then
    if ! authselect check; then
echo "
authselect integrity check failed. Remediation aborted!
This remediation could not be applied because an authselect profile was not selected or the selected profile is not intact.
It is not recommended to manually edit the PAM files when authselect tool is available.
In cases where the default authselect profile does not cover a specific demand, a custom authselect profile is recommended."
exit 1
fi
authselect enable-feature without-nullok

authselect apply-changes -b
else

if grep -qP '^\s*auth\s+'"sufficient"'\s+pam_unix.so\s.*\bnullok\b' "/etc/pam.d/system-auth"; then
    sed -i -E --follow-symlinks 's/(.*auth.*'"sufficient"'.*pam_unix.so.*)\snullok=?[[:alnum:]]*(.*)/\1\2/g' "/etc/pam.d/system-auth"
fi

if grep -qP '^\s*password\s+'"sufficient"'\s+pam_unix.so\s.*\bnullok\b' "/etc/pam.d/system-auth"; then
    sed -i -E --follow-symlinks 's/(.*password.*'"sufficient"'.*pam_unix.so.*)\snullok=?[[:alnum:]]*(.*)/\1\2/g' "/etc/pam.d/system-auth"
fi

if grep -qP '^\s*auth\s+'"sufficient"'\s+pam_unix.so\s.*\bnullok\b' "/etc/pam.d/password-auth"; then
    sed -i -E --follow-symlinks 's/(.*auth.*'"sufficient"'.*pam_unix.so.*)\snullok=?[[:alnum:]]*(.*)/\1\2/g' "/etc/pam.d/password-auth"
fi

if grep -qP '^\s*password\s+'"sufficient"'\s+pam_unix.so\s.*\bnullok\b' "/etc/pam.d/password-auth"; then
    sed -i -E --follow-symlinks 's/(.*password.*'"sufficient"'.*pam_unix.so.*)\snullok=?[[:alnum:]]*(.*)/\1\2/g' "/etc/pam.d/password-auth"
fi
fi

else
    >&2 echo 'Remediation is not applicable, nothing was done'
fi

# V-230537, V-230540, V-230541, V-230542, V-230545, V-230546, V-230280, V-230311, V-230269, V-230270, V-230266, V-230548
# Define the sysctl configuration file
SYSCTL_CONF="/etc/sysctl.conf"

# Backup the original sysctl.conf file
sudo cp "$SYSCTL_CONF" "$SYSCTL_CONF.bak"

# Add or update the required lines in /etc/sysctl.conf
{
    echo "net.ipv4.icmp_echo_ignore_broadcasts=1"
    echo "net.ipv6.conf.all.forwarding=0"
    echo "net.ipv6.conf.all.accept_ra=0"
    echo "net.ipv6.conf.default.accept_ra=0"
    echo "kernel.unprivileged_bpf_disabled=1"
    echo "kernel.yama.ptrace_scope=1"
    echo "kernel.randomize_va_space=2"
    echo "kernel.core_pattern=|/bin/false"
    echo "kernel.dmesg_restrict=1"
    echo "kernel.perf_event_paranoid=2"
    echo "kernel.kexec_load_disabled=1"
} | sudo tee "$SYSCTL_CONF" > /dev/null

# Check if the command was successful
if [ $? -eq 0 ]; then
    echo "Sysctl parameters have been added/updated successfully."
else
    echo "Failed to update sysctl parameters."
    exit 1
fi

# Reload sysctl settings
sudo sysctl --system

# Check if the reload command was successful
if [ $? -eq 0 ]; then
    echo "Sysctl settings reloaded successfully."
else
    echo "Failed to reload sysctl settings."
    exit 1
fi

echo "All changes have been applied successfully."

# V-230471
sudo chmod 0640 /etc/audit/rules.d/audit.rules
sudo chmod 0640 /etc/audit/rules.d/99-finalize.rules
sudo chmod 0640 /etc/audit/auditd.conf

#Console_Banner

#!/bin/bash

# Define the banner text
BANNER_TEXT=" - NOTICE -\n\nWarning: This is a monitored device or computer system. Illegal and/or unauthorized use of this device and any related service is strictly prohibited and appropriate legal action will be taken, including without limitation civil, criminal and injunctive redress.\nYour use of this device and any related service constitutes your consent to be bound by all terms, conditions, and notices associated with its use including consent to all monitoring and disclosure provisions."

# Write the banner text to /etc/issue
echo -e "$BANNER_TEXT" | sudo tee /etc/issue > /dev/null

# Optionally, print a message indicating success
echo "Banner added to /etc/issue." 

# Putty_Banner

#!/bin/bash

# Step 1: Create the banner file with specified content
BANNER_FILE="/etc/banner"

# Create the banner file with the specified message
cat <<EOL | sudo tee $BANNER_FILE > /dev/null
 - NOTICE -

Warning: This is a monitored device or computer system. Illegal and/or
unauthorized use of this device and any related service is strictly
prohibited and appropriate legal action will be taken, including
without limitation civil, criminal and injunctive redress.
Your use of this device and any related service constitutes
your consent to be bound by all terms, conditions, and notices
associated with its use including consent to all monitoring and disclosure provisions.
EOL

# Step 2: Update the sshd_config to include the Banner directive
SSHD_CONFIG="/etc/ssh/sshd_config"

# Backup the original sshd_config file
sudo cp $SSHD_CONFIG "$SSHD_CONFIG.bak"

# Check if Banner directive already exists; if so, update it; otherwise, add it
if grep -q "^#*Banner" $SSHD_CONFIG; then
    sudo sed -i "s|^#*Banner.*|Banner $BANNER_FILE|" $SSHD_CONFIG
else
    echo "Banner $BANNER_FILE" | sudo tee -a $SSHD_CONFIG > /dev/null
fi

# Restart SSH service to apply changes
sudo systemctl restart sshd

# Print success message
echo "SSH banner has been set to: $BANNER_FILE"

# twistlock scripts

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
sudo sed -i 's/^#*PermitRootLogin.*$/PermitRootLogin no/' /etc/ssh/sshd_config
sudo systemctl restart sshd

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

