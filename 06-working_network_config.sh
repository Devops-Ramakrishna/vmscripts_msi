#!/bin/bash

currnetdir=$PWD
logfile=$currnetdir/network_config.log
file=$1

Print2Log()
{
    msg=$1
    echo "[`date +%x_%H:%M:%S:%3N`] ${msg}" >>$logfile
}

usage="\t Wrong option Given, Usage: sh $0 $1\n
       \t Example: sh $0 <path>/interface.ini\n
       \t sh $0 /home/cpeinfra/interface.ini\n"

       if [[ -z $1 ]]; then
           echo -ne "$usage" | tee -a $logfile
           exit 1
       fi

main (){


read_ip_from_file $file

if [ "$method" == "static" ]; then

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


    Print2Log "Entered IPv4 dnsserverip address: $dnsserverip"

    if validate_ip $dnsserverip; then
        Print2Log "${dnsserverip} is a valid IPv4 dnsserverip address."
    else
        Print2Log "${dnsserverip} is a invalid IPv4 dnsserverip address."
        echo -ne "${gateway} is a invalid IPv4 dnsserverip address.\n"
        exit 1
    fi

    Print2Log "Verify if Active network interface is available"
    validate_interface
    if [ $? -eq 0 ]; then
        Print2Log "Active network interface is: $interface"
    else
        Print2Log "No active network interface found."
        echo -ne "No active network interface found.... please check the virtaul manchine network configuration\n"
        exit 1
    fi


    if check_file_exists $interface; then
        Print2Log "File $interface exists."
    else
       Print2Log "File $interface does not exist."
    fi


    update_network_config $ipaddress $netmask $gateway $interface $dnsserverip

    restart_network_manager

    #down_network_connection $interface

    up_network_connection $interface

    obs_prereq

    install_filebeat

    install_telemetry

elif [ "$method" == "dhcp" ]; then

    obs_prereq

    install_filebeat

    install_telemetry

else
    Print2Log "Error: Invalid 'method' value in the interface.ini file. Allowed values are 'static' or 'dhcp'."
    echo "Error: Invalid 'method' value in the interface.ini file. Allowed values are 'static' or 'dhcp'."
    exit 1
fi

}

read_ip_from_file() {
    file_path=$1
    if [ -f "$file_path" ]; then
        ipaddress=$(cat "$file_path" | grep -i ipaddress | awk -F '=' '{print $NF}' | tr -d '\n')
        netmask=$(cat "$file_path" | grep -i netmask | awk -F '=' '{print $NF}' | tr -d '\n')
        gateway=$(cat "$file_path" | grep -i gateway | awk -F '=' '{print $NF}' | tr -d '\n')
        dnsserverip=$(cat "$file_path" | grep -i dnsserverip | awk -F '=' '{print $NF}' | tr -d '\n')
        method=$(cat "$file_path" | grep -i method | awk -F '=' '{print $NF}' | tr -d '\n')
    else
        echo "File not found: $file_path"
        exit 1
    fi
}

validate_ip() {
    local ip=$1
    local stat=1

    if [[ $ip =~ ^[0-9]{1,3}\.[0-9]{1,3}\.[0-9]{1,3}\.[0-9]{1,3}$ ]]; then
        OIFS=$IFS
        IFS='.'
        ip=($ip)
        IFS=$OIFS
        [[ ${ip[0]} -le 255 && ${ip[1]} -le 255 && ${ip[2]} -le 255 && ${ip[3]} -le 255 ]]
        stat=$?
    fi

    return $stat
}


validate_subnetmask() {
  local subnetmask=$1

  if [[ $subnetmask -ge 1 && $subnetmask -le 32 ]]; then
    return 0
  else
    return 1
  fi
}


validate_interface(){
    interface=$(ip addr show | grep "state UP" | awk -F ': ' '{print $2}'| head -1)

    if [ -n "$interface" ]; then
        return 0
    else
        return 1
    fi

}


check_file_exists() {
    local file="/etc/NetworkManager/system-connections/$interface.nmconnection"

    if [ -f "$file" ]; then
        return 0
    else
        return 1
    fi
}

function update_network_config {
  ip="$1"
  mask="$2"
  gw="$3"
  iface="$4"
  dnsserverip="$5"

  Print2Log "Configuring ipaddress $ip/$mask gateway $gw to interface $iface"

  nmcli con mod $iface ipv4.method static ipv4.addresses $ip/$mask ipv4.gateway $gw ipv4.dns $dnsserverip

  Print2Log "Printing connection output"

  nmcli connection show >> $logfile

}

restart_network_manager() {

    Print2Log "Restart NetworkManager service"
    systemctl restart NetworkManager
}

down_network_connection() {
    local interface=$1
    Print2Log "Bringing down $1 interface"
    nmcli connection down $1
}

up_network_connection() {
    local interface=$1
    Print2Log "Bringing up $1 interface"
    nmcli connection up $1
    Print2Log "Printing ipaddress assigned to $iface"
    ip address | grep $iface >> $logfile
}
obs_prereq(){
        Print2Log "Copying file containers.conf to /etc/containers/" >> $logfile
        sudo cp /usr/share/containers/containers.conf /etc/containers/
        if [ $? -eq 0 ]; then
           Print2Log "Copy operation successful" >> $logfile
        else
           Print2Log "Copy operation failed" >> $logfile
           exit 1
        fi

        sudo sed -i 's/^log_driver = "k8s-file"/log_driver = "journald"/' /etc/containers/containers.conf
        sudo sed -i 's/^#events_logger = "journald"/events_logger = "journald"/' /etc/containers/containers.conf
        sudo sed -i 's/^events_logger = "file"/#events_logger = "file"/' /etc/containers/containers.conf
        Print2Log "Updating log_driver and events_logger in /etc/containers/containers.conf" >> $logfile
}
install_filebeat(){
        sudo bash $currnetdir/filebeat-install-edge.sh
        if [ $? -ne 0 ];then
            exit 1
        else
            Print2Log "Filebeat installation successful"
        fi
}


install_telemetry(){
        sudo bash $currnetdir/install_telemetry.sh
        if [ $? -ne 0 ];then
           exit 1
        else
           Print2Log "telemetry script installation successful"
        fi
}

main

echo "Script execution completed"
