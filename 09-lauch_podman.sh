#!/bin/bash
currnetdir=/root
logfile=$currnetdir/network_config.log

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
    podman login -u $username -p $password
    echo " podman login successfully completed "
    sudo podman pull docker.io/library/httpd:latest
    echo " images has been downloaded from registry "
}

create_container() {
  echo "***Starting to create container for httpd"
  sudo podman volume create httpd
  podman run -dt -p 8080:80/tcp docker.io/library/httpd
  echo " container has been lauched successfully "
}

download_image
create_container
