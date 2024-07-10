#!/bin/bash

currnetdir=$PWD
logfile=$currnetdir/lauch_podman.log

Print2Log()
{
    msg=$1
    echo "[`date +%x_%H:%M:%S:%3N`] ${msg}" >>$logfile
}

usage="\t Wrong option Given, Usage: sh $0 $1\n
       \t Example: sh $0 <path>/podman_credentials.ini\n
       \t sh $0 $PWD/podman_credentials.ini\n"

if [[ -z $1 ]]; then
    echo -ne "$usage" | tee -a $logfile
    exit 1
fi

file_path="$PWD/podman_credentials.ini"
download_image() {
    username=$(sudo cat "$file_path" | grep -i username | awk -F '=' '{print $NF}' | tr -d '\n')
    password=$(sudo cat "$file_path" | grep -i password | awk -F '=' '{print $NF}' | tr -d '\n')
    podman login registry.connect.redhat.com -u $username -p $password
    echo " podman login successfully completed "

    # Check if the image is already present
    if sudo podman images | awk -v repo="docker.io/library/httpd" -v tag="latest" '$1 == repo && $2 == tag {found=1} END{if(found) exit 0; else exit 1}'; then
        echo "Image 'docker.io/library/httpd:latest' already exists. Skipping download."
    else
        sudo podman pull docker.io/library/httpd:latest
        echo " Image has been downloaded from registry "
    fi
}

create_container() {
    echo " Starting to create container for httpd"

    # Check if the container is already running
    if sudo podman ps -a | awk -v name="httpd" '$NF == name {found=1} END{if(found) exit 0; else exit 1}'; then
        echo "Container 'httpd' already exists. Skipping container creation."
    else
        sudo podman volume create httpd
        podman run -dt -p 8080:80/tcp docker.io/library/httpd
        echo " Container has been launched successfully "
    fi
}

download_image
create_container

echo "Script execution completed."
