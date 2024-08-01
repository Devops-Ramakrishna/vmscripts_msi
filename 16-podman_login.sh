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

if podman login "$registry" -u "$username" -p "$password"; then
        Print2Log "Podman login successfully completed."
    else
        Print2Log "Error: Podman login failed."
        exit 1
    fi
}
download_image
Print2Log "Script execution completed successfully."