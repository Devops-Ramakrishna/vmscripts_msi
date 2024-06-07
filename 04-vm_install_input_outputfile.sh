#!/bin/bash

currnetdir=$PWD
logfile=$currnetdir/vm_install.log

Print2Log()
{
    msg=$1
    echo "[date +%x_%H:%M:%S:%3N] ${msg}" >> $logfile
}

usage=" \n\t Wrong option Given, Usage: sh $0 $1
       \n\t Example: sh $0 input_file "

       if [[ -z $1 ]]; then
           echo -ne "$usage" | tee -a $logfile
           exit 1
       fi
       

# Assign arguments to variables
input_file=$1

# Read the input file
while IFS=',' read -r vm_name memory_size vcpus disk_size os_variant iso_path
do
  # Check if CPU is above 8
  if [ $vcpus -gt 8 ]; then
    echo "CPU value is above 8, script will not execute" >> "$logfile"
    continue
  fi

  # Check if memory is above 128
  if [ $memory_size -gt 128 ]; then
    echo "Memory value is above 128, script will execute" >> "$logfile"
    continue
  fi

  # Check if disk size is below 50 GB
  if [ $disk_size -lt 50 ]; then
    echo "Disk size is below 50 GB, script will not execute" >> "$logfile"
    continue
  fi

  # Run the virt-install command
  virt-install --name "$vm_name" --memory "$memory_size" --vcpus "$vcpus" --disk size="$disk_size"  --os-variant "$os_variant" --import -l "$iso_path" --graphics none --extra-args="inst.ks=hd:LABEL=RHEL-9-4-0-BaseOS-x86_64:/ks.cfg console=tty0 console=ttyS0,115200n8 inst.repo=cdrom" --network network=default --check disk_size=off >> "$output_file"
done >> "$logfile"
