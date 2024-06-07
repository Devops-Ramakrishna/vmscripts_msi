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

# Initialize variables
vm_name=$(awk -F'=' '/vm_name/ {print $2}' "$1")
memory_size_kb=$(awk -F'=' '/memory_size_kb/ {print $2}' "$1")
vcpus=$(awk -F'=' '/vcpus/ {print $2}' "$1")
disk_size_gb=$(awk -F'=' '/disk_size_gb/ {print $2}' "$1")
iso_name=$(awk -F'=' '/iso_name/ {print $2}' "$1")
ip_address=$(awk -F'=' '/ip_address/ {print $2}' "$1")
netmask=$(awk -F'=' '/netmask/ {print $2}' "$1")
gateway=$(awk -F'=' '/gateway/ {print $2}' "$1")

# Read the input file
while IFS='=' read -r key value
do
    case $key in
        "vm_name") vm_name="$value" ;;
        "memory_size_kb") memory_size_kb="$value" ;;
        "vcpus") vcpus="$value" ;;
        "disk_size_gb") disk_size_gb="$value" ;;
        "iso_name") iso_name="$value" ;;
        "ip_address") ip_address="$value" ;;
        "netmask") netmask="$value" ;;
        "gateway") gateway="$value" ;;
    esac
done < "$input_file"

# Check if the required variables are set
if [ -z "$vm_name" ]; then
    Print2Log "Error: VM name cannot be empty."
    exit 1
fi

if [ -z "$memory_size_kb" ]; then
    Print2Log "Error: Memory size cannot be empty."
    exit 1
fi

if [ -z "$vcpus" ]; then
    Print2Log "Error: Number of vCPUs cannot be empty."
    exit 1
fi

if [ -z "$disk_size_gb" ]; then
    Print2Log "Error: Disk size cannot be empty."
    exit 1
fi

if [ -z "$iso_name" ]; then
    Print2Log "Error: ISO name cannot be empty."
    exit 1
fi

if [ -z "$ip_address" ]; then
    Print2Log "Error: IP address cannot be empty."
    exit 1
fi

if [ -z "$netmask" ]; then
    Print2Log "Error: Netmask cannot be empty."
    exit 1
fi

if [ -z "$gateway" ]; then
    Print2Log "Error: Gateway cannot be empty."
    exit 1
fi

# Run the virt-install command
virt-install --name "$vm_name" --memory "$memory_size_kb" --vcpus "$vcpus" --disk size="$disk_size_gb"  --os-variant "rhel9.0" --import -l "$iso_name" --graphics none --extra-args="inst.ks=hd:LABEL=RHEL-9-4-0-BaseOS-x86_64:/ks.cfg console=tty0 console=ttyS0,115200n8 inst.repo=cdrom" --network network=default --check disk_size=off >> "$logfile"
