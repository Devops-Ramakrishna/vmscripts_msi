#!/bin/bash
# Remediation is applicable only in certain platforms
# V-230244
if [ ! -f /.dockerenv ] && [ ! -f /run/.containerenv ]; then

var_sshd_set_keepalive='1'


if [ -e "/etc/ssh/sshd_config" ] ; then

    LC_ALL=C sed -i "/^\s*ClientAliveCountMax\s\+/Id" "/etc/ssh/sshd_config"
else
    touch "/etc/ssh/sshd_config"
fi
# make sure file has newline at the end
sed -i -e '$a\' "/etc/ssh/sshd_config"

cp "/etc/ssh/sshd_config" "/etc/ssh/sshd_config.bak"
# Insert at the beginning of the file
printf '%s\n' "ClientAliveCountMax $var_sshd_set_keepalive" > "/etc/ssh/sshd_config"
cat "/etc/ssh/sshd_config.bak" >> "/etc/ssh/sshd_config"
# Clean up after ourselves.
rm "/etc/ssh/sshd_config.bak"

else
    >&2 echo 'Remediation is not applicable, nothing was done'
fi

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
if rpm --quiet -q systemd; then

if [ -e "/etc/systemd/coredump.conf" ] ; then

    LC_ALL=C sed -i "/^\s*Storage\s*=\s*/Id" "/etc/systemd/coredump.conf"
else
    touch "/etc/systemd/coredump.conf"
fi
# make sure file has newline at the end
sed -i -e '$a\' "/etc/systemd/coredump.conf"

cp "/etc/systemd/coredump.conf" "/etc/systemd/coredump.conf.bak"
# Insert at the end of the file
printf '%s\n' "Storage=none" >> "/etc/systemd/coredump.conf"
# Clean up after ourselves.
rm "/etc/systemd/coredump.conf.bak"

else
    >&2 echo 'Remediation is not applicable, nothing was done'
fi

# Remediation is applicable only in certain platforms
# V-230315
if rpm --quiet -q systemd; then

if [ -e "/etc/systemd/coredump.conf" ] ; then

    LC_ALL=C sed -i "/^\s*ProcessSizeMax\s*=\s*/Id" "/etc/systemd/coredump.conf"
else
    touch "/etc/systemd/coredump.conf"
fi
# make sure file has newline at the end
sed -i -e '$a\' "/etc/systemd/coredump.conf"

cp "/etc/systemd/coredump.conf" "/etc/systemd/coredump.conf.bak"
# Insert at the end of the file
printf '%s\n' "ProcessSizeMax=0" >> "/etc/systemd/coredump.conf"
# Clean up after ourselves.
rm "/etc/systemd/coredump.conf.bak"

else
    >&2 echo 'Remediation is not applicable, nothing was done'
fi

# Remediation is applicable only in certain platforms
# V-230330
if [ ! -f /.dockerenv ] && [ ! -f /run/.containerenv ]; then

if [ -e "/etc/ssh/sshd_config" ] ; then

    LC_ALL=C sed -i "/^\s*PermitUserEnvironment\s\+/Id" "/etc/ssh/sshd_config"
else
    touch "/etc/ssh/sshd_config"
fi
# make sure file has newline at the end
sed -i -e '$a\' "/etc/ssh/sshd_config"

cp "/etc/ssh/sshd_config" "/etc/ssh/sshd_config.bak"
# Insert at the beginning of the file
printf '%s\n' "PermitUserEnvironment no" > "/etc/ssh/sshd_config"
cat "/etc/ssh/sshd_config.bak" >> "/etc/ssh/sshd_config"
# Clean up after ourselves.
rm "/etc/ssh/sshd_config.bak"

else
    >&2 echo 'Remediation is not applicable, nothing was done'
fi

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