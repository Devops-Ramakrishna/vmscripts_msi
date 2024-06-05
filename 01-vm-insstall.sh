#!/bin/bash

# Check if the correct number of arguments are passed
if [ "$#" -ne 6 ]; then
  echo "Usage: $0 <vm_name> <memory_size> <vcpus> <disk_size> <os_variant> <iso_path>"
  exit 1
fi

# Assign arguments to variables
vm_name=$1
memory_size=$2
vcpus=$3
disk_size=$4
os_variant=$5
iso_path=$6

# Run the virt-install command

virt-install --name "$vm_name" --memory "$memory_size" --vcpus "$vcpus" --disk size="$disk_size"  --os-variant "$os_variant" --import -l "$iso_path" --graphics none --extra-args="inst.ks=hd:LABEL=RHEL-9-4-0-BaseOS-x86_64:/ks.cfg console=tty0 console=ttyS0,115200n8 inst.repo=cdrom" --network network=default --check disk_size=off

# Inform the user
echo "VM "$vm_name" is being installed with the provided parameters"

# sh -x /root/vm_install.sh ramvm 4096 4 20 rhel9.0 /var/lib/libvirt/images/CPE-RHEL-9.4-x86_64.290520241942.iso