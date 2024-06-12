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
# Validate vCPUs
    if [ $vcpus -gt 8 ]; then # above 8 it should not work
        Print2Log "Number of vCPUs is greater than 8."
        echo -ne "Number of vCPUs is greater than 8.\n"
        exit 1
    fi

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

validate_ip() {
    local ip=$1 # This line declares a local variable ip and assigns it the value of the first command-line argument passed to the function.
    local stat=1 # This line declares a local variable stat and initializes it to 1. This variable will be used to track the status of the validation.

    if [[ $ip =~ ^[0-9]{1,3}\.[0-9]{1,3}\.[0-9]{1,3}\.[0-9]{1,3}$ ]]; then
        OIFS=$IFS
        IFS='.' 
        ip=($ip)
        IFS=$OIFS # This line splits the IP address into its four components (octets) using the dot (.) as a delimiter. It does this by temporarily setting the internal field separator (IFS) to a dot and then splitting the IP address into an array using the () syntax.
        [[ ${ip[0]} -le 255 && ${ip[1]} -le 255 && ${ip[2]} -le 255 && ${ip[3]} -le 255 ]] # This line checks if each octet of the IP address is within the valid range of 0 to 255.
        stat=$? # This line sets the stat variable to the exit status of the last command. If the IP address is valid, stat will be 0; otherwise, it will be 1.
    fi
    return $stat # This line returns the stat variable, which indicates whether the IP address is valid or not.
}

validate_subnetmask() {
  local subnetmask=$1

  if [[ $subnetmask -ge 1 && $subnetmask -le 32 ]]; then # This line checks if the subnet mask is within the valid range of 1 to 32. The subnet mask is typically represented as a number from 1 to 32, where 1 represents a full subnet and 32 represents a single host.
    return 0 # If the subnet mask is within the valid range, the function returns a status code of 0, indicating that the subnet mask is valid.
  else
    return 1 # If the subnet mask is not within the valid range, the function returns a status code of 1, indicating that the subnet mask is invalid.
  fi
}

# Validate gateway
validate_gateway(){
    local gateway=$1
    local stat=1

    if [[ $gateway =~ ^[0-9]{1,3}\.[0-9]{1,3}\.[0-9]{1,3}\.[0-9]{1,3}$ ]]; then
        OIFS=$IFS
        IFS='.'
        gateway=($gateway)
        IFS=$OIFS
        [[ ${gateway[0]} -le 255 && ${gateway[1]} -le 255 && ${gateway[2]} -le 255 && ${gateway[3]} -le 255 ]]
        stat=$?
    fi

    return $stat
}

# Validate memory size
validate_memory() {
    if [[ $memory_size_kb =~ ^[0-9]+$ ]]; then
        Print2Log "Entered memory size: $memory_size_kb"
        if (( $memory_size_kb < 131072 )); then  # memory size should be 131072
            Print2Log "Memory size is less than 1024 KB."
            echo -ne "Memory size is less than 1024 KB.\n"
            exit 1
        fi
    else
        Print2Log "Invalid memory size."
        echo -ne "Invalid memory size.\n"
        exit 1
    fi
}

# Validate disk size
validate_disksize(){
    if [[ $disk_size_gb =~ ^[0-9]+$ ]]; then
        Print2Log "Entered disk size: $disk_size_gb"
        if (( $disk_size_gb < 50 )); then # disk size is above 50
            Print2Log "Disk size is less than 1 GB."
            echo -ne "Disk size is less than 1 GB.\n"
            exit 1
        fi
    else
        Print2Log "Invalid disk size."
        echo -ne "Invalid disk size.\n"
        exit 1
    fi
}

# Run the script
main $input_file

virt-install --name $vmname --memory $memory_size_kb --vcpus $vcpus --disk size="$disk_size_gb" --os-variant rhel9.4 --import -l /var/lib/libvirt/images/CPE-RHEL-9.4-x86_64.290520241942.iso   --graphics none --extra-args="inst.ks=hd:LABEL=RHEL-9-4-0-BaseOS-x86_64:/ks.cfg console=ttyS0 console=ttyS0,115200n8 inst.repo=cdrom" --network=bridge:bridge0 --extra-args "ip=$ipaddress::$gateway:$netmask:test.example.com:enp1s0:none" --check disk_size=off