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
file=$1

main (){

read_ip_from_file $file

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

if validate_ip $gateway; then
    Print2Log "${gateway} is a valid IPv4 gateway address."
else
    Print2Log "${gateway} is a invalid IPv4 gateway address."
    echo -ne "${gateway} is a invalid IPv4 gateway address.\n"
    exit 1
fi
}

# Initialize variables
vm_name=$(awk -F'=' '/vm_name/ {print $2}' "$1")
memory_size_kb=$(awk -F'=' '/memory_size_kb/ {print $2}' "$1")
vcpus=$(awk -F'=' '/vcpus/ {print $2}' "$1")
disk_size_gb=$(awk -F'=' '/disk_size_gb/ {print $2}' "$1")
iso_name=$(awk -F'=' '/iso_name/ {print $2}' "$1")
ip_address=$(awk -F'=' '/ip_address/ {print $2}' "$1")
netmask=$(awk -F'=' '/netmask/ {print $2}' "$1")
gateway=$(awk -F'=' '/gateway/ {print $2}' "$1")

# Check if the required variables are set
if [[ -z "$vm_name" || -z "$memory_size_kb" || -z "$vcpus" || -z "$disk_size_gb" || -z "$iso_name" || -z "$ip_address" || -z "$netmask" || -z "$gateway" ]]; then
    Print2Log "Error: input_file cannot be empty."
    exit 1
fi




