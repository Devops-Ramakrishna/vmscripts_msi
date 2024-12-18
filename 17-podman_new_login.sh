#!/bin/bash

currnetdir=$PWD
logfile=$currnetdir/podman_login.log

Print2Log()
{
    msg=$1
    echo "[`date +%x_%H:%M:%S:%3N`] ${msg}" >>$logfile
}

usage="\t Wrong option Given, Usage: sh $0 $1\n
       \t Example: sh $0 <path>/interface.ini\n"

if [[ -z $1 ]]; then
    echo -ne "$usage" | tee -a $logfile
    exit 1
fi

file_path=$1
echo " passed the interface.ini file "
download_image() {
    registry=$(sudo cat "$file_path" | grep -i registry | awk -F '=' '{print $NF}')
    username=$(sudo cat "$file_path" | grep -i username | awk -F '=' '{print $NF}')
    password=$(sudo cat "$file_path" | grep -i password | awk -F '=' '{print $NF}')
}
podman_login_home() {
        podman login --authfile /var/home/cpeinfra/.config/containers/auth.json "$registry" -u "$username" -p "$password"
        if [ $? -eq 0 ];then
                Print2Log "Podman login successfully completed with normal user"
        else
                Print2Log "Error: Podman login failed."
                exit 1
        fi
}
podman_login_root() {
        sudo podman login --authfile /root/.config/containers/auth.json "$registry" -u "$username" -p "$password"
        if [ $? -eq 0 ];then
                Print2Log "Podman login successfully completed."
        else
                Print2Log "Error: Podman login failed."
                exit 1
        fi
}
download_image
podman_login_home
podman_login_root
