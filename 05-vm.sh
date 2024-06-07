#!/bin/bash

# Set the current directory and log file
currnetdir=$PWD
logfile=$currnetdir/vm_install.log

# Function to print logs
Print2Log() {
    msg=$1
    echo "[date +%x_%H:%M:%S:%3N] ${msg}" >> $logfile
}

# Usage message
usage=" \n\t Wrong option Given, Usage: sh $0 $1
       \n\t Example: sh $0 input_file\n "

# Check if the correct number of arguments are passed
if [[ "$#" -ne 1 || -z $1 ]]; then
    echo -ne "$usage" | tee -a $logfile
    exit 1
fi

# Assign arguments to variables
input_file=$1

main (){

read_vm_from_file $input_file

Print2Log "Entered memory_size_kb : $memory_size_kb"

if validate_memory $memory_size_kb; then
    Print2Log "${memory_size_kb} is a valid memory size."
else
    Print2Log "${memory_size_kb} is a invalid memory size."
    echo -ne "${memory_size_kb} is a invalid memory size.\n"
    exit 1
fi

Print2Log "Entered disk_size_gb : $disk_size_gb"

if validate_disksize $disk_size_gb; then
    Print2Log "${disk_size_gb} is a valid disk size."
else
    Print2Log "${disk_size_gb} is a invalid disk size."
    echo -ne "${disk_size_gb} is a invalid disk size.\n"
    exit 1
fi

Print2Log "Entered IPv4 address: $ipaddress"

if validate_ip $ipaddress; then
    Print2Log "${ipaddress} is a valid IPv4 address."
else
    Print2Log "${ipaddress} is a invalid IPv4 address."
    echo -ne "${ipaddress} is a invalid IPv4 address.\n"
    exit 1
fi

Print2Log "Entered subnetmask: $netmask"

if validate_subnetmask $netmask; then
    Print2Log "The subnet mask $netmask is valid."
else
    Print2Log "The subnet mask $netmask is not valid."
    echo -ne "The subnet mask $netmask is not valid.\n"
   exit 1
fi


Print2Log "Entered IPv4 gateway address: $gateway"

if validate_gateway $gateway; then
    Print2Log "${gateway} is a valid IPv4 gateway address."
else
    Print2Log "${gateway} is a invalid IPv4 gateway address."
    echo -ne "${gateway} is a invalid IPv4 gateway address.\n"
    exit 1
fi
}

# Initialize variables
read_vm_from_file() {
    input_file=$1
    if [ -f "$input_file" ]; then
        vmname=$(cat "input_file" | grep -i vmname | awk -F "=" '{print $2}')
        memory_size_kb=$(cat "input_file" | grep -i memory_size_kb | awk -F "=" '{print $2}')
        vcpus=$(cat "input_file" | grep -i vcpus | awk -F "=" '{print $2}')
        disk_size_gb=$(cat "input_file" | grep -i disk_size_gb | awk -F "=" '{print $2}')
        iso_name=$(cat "input_file" | grep -i iso_name | awk -F "=" '{print $2}')
        ipaddress=$(cat "input_file" | grep -i ipaddress | awk -F "=" '{print $2}')
        netmask=$(cat "input_file" | grep -i netmask | awk -F "=" '{print $2}')
        gateway=$(cat "input_file" | grep -i gateway | awk -F "=" '{print $2}')

    else
        echo "File not found: $input_file"
        exit 1
    fi
}

virt-install --name $vmname --memory $memory_size_kb --vcpus $vcpus --disk size="$disk_size_gb" --os-variant rhel9.4 --import -l /var/lib/libvirt/images/CPE-RHEL-9.4-x86_64.290520241942.iso   --graphics none --extra-args="inst.ks=hd:LABEL=RHEL-9-4-0-BaseOS-x86_64:/ks.cfg console=tty0 console=ttyS0,115200n8 inst.repo=cdrom" --network=bridge:bridge0 --extra-args "$ipadress::$gateway:$netmask:test.example.com:enp1s0:none" --check disk_size=off






