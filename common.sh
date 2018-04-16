#!/bin/bash

##############################################
##
##   Mini-DMZ Setup Script Common Function Lib
##
##   Version: 0.1
##
##   C.Keslar
##
###############################################


OCTET="(25[0-5]|2[0-4][0-9]|1[0-9][0-9]|[1-9]?[0-9])"
IP4="^$OCTET\\.$OCTET\\.$OCTET\\.$OCTET$"
   
HOSTNAME_FILE="/etc/hostname"
DHCPCD_FILE="/etc/dhcpcd.conf"
HOSTS_FILE="/etc/hosts"
DNS_FILE="/etc/resolv.conf.dmz"
INTERFACES_FILE="/etc/network/interfaces"

# Configure the keyboard
do_configure_keyboard() {
  printf "Reloading keymap. This may take a short while\n"
  if [ "$INTERACTIVE" = True ]; then
    dpkg-reconfigure keyboard-configuration
    # sed -i -e '/sgb/us/g' /etc/default/keyboard
  else
    local KEYMAP="$1"
    sed -i /etc/default/keyboard -e "s/^XKBLAYOUT.*/XKBLAYOUT=\"$KEYMAP\"/"
    dpkg-reconfigure -f noninteractive keyboard-configuration
  fi
  invoke-rc.d keyboard-setup start
  setsid sh -c 'exec setupcon -k --force <> /dev/tty1 >&0 2>&1'
  udevadm trigger --subsystem-match=input --action=change
  return 0
}

# Set the timezone
do_change_timezone() {
  if [ "$INTERACTIVE" = True ]; then
    dpkg-reconfigure tzdata
  else
    local TIMEZONE="$1"
    if [ ! -f "/usr/share/zoneinfo/$TIMEZONE" ]; then
      return 1;
    fi
    rm /etc/localtime
    echo "$TIMEZONE" > /etc/timezone
    dpkg-reconfigure -f noninteractive tzdata
  fi
}

# Update the hostname for this Pi
do_hostname() {
  if [ "$INTERACTIVE" = True ]; then
    whiptail --title "Setting Device Hostname" --msgbox "\
Please note: RFCs mandate that a hostname's labels \
may contain only the ASCII letters 'a' through 'z' (case-insensitive), 
the digits '0' through '9', and the hyphen.
Hostname labels cannot begin or end with a hyphen. 
No other symbols, punctuation characters, or blank spaces are permitted.\
" 20 70 1
  fi
  CURRENT_HOSTNAME=`cat /etc/hostname | tr -d " \t\n\r"`
  if [ "$INTERACTIVE" = True ]; then
    NEW_HOSTNAME=$(whiptail --title "Set Hostname" --inputbox "Please enter a hostname" 20 60 "$CURRENT_HOSTNAME" 3>&1 1>&2 2>&3)
  else
    NEW_HOSTNAME=$1
    true
  fi
  if [ $? -eq 0 ]; then
    echo $NEW_HOSTNAME > /etc/hostname
    sed -i "s/127.0.1.1.*$CURRENT_HOSTNAME/127.0.1.1\t$NEW_HOSTNAME/g" /etc/hosts
    ASK_TO_REBOOT=1
  fi
}

# Create a new user 
do_newuser() {
   # Ask user for new user name
   NEWUSER=$(whiptail --title "Create New User" --inputbox "Enter and new system username" 20 60 3>&1 1>&2 2>&3)
   NEWNAME=$(whiptail --title "Create New User" --inputbox "Enter full name" 20 60 3>&1 1>&2 2>&3)
   NEWPASS=$(whiptail --title "Create New User" --passwordbox "Enter password" 20 60 3>&1 1>&2 2>&3)
   
   # Create the user
   useradd -c "$NEWNAME" $NEWUSER -d /home/$NEWUSER
   mkdir /home/$NEWUSER
   chown $NEWUSER:$NEWUSER /home/$NEWUSER
   chomd 700 /home/$NEWUSER
   
   # Set the password
   echo "$NEWUSER:$NEWPASS" | chpasswd
   # Add the user to the sudoer's group
   usermod -aG sudo $NEWUSER
}

# Set the static IP address information for 
do_set_eth0(){
   # echo "supersede domain-name-servers 8.8.8.8, 8.8.4.4;" >> $DHCPCD_FILE
   # echo "ipv4only" >> $DHCPCD_FILE
   #echo "interface eth0" >> $DHCPCD_FILE
   #echo "static ip_address=192.168.0.1/24" >> $DHCPCD_FILE
   echo "auto lo" >> $INTERFACES_FILE
   echo "   iface lo inet loopback" >> $INTERFACES_FILE
   echo "" >> $INTERFACES_FILE
   echo "auto wlan0" >> $INTERFACES_FILE
   echo "iface wlan0 inet dhcp" >> $INTERFACES_FILE
   echo "   wpa-conf /etc/wpa_supplicant/wpa_supplicant.conf" >> $INTERFACES_FILE
   echo "" >> $INTERFACES_FILE
   echo "auto eth0" >> $INTERFACES_FILE
   echo "iface eth0 inet static" >> $INTERFACES_FILE
   echo "  address 192.168.0.1" >> $INTERFACES_FILE
   echo "  netmask 255.255.255.0" >> $INTERFACES_FILE
   echo "  broadcast 192.168.0.255"  >> $INTERFACES_FILE
   echo "  network 192.168.1.0" >> $INTERFACES_FILE

   # Exclude eth0 from DHCPCD_FILE
   echo "denyinterfaces eth0" >> $DHCPCD_FILE
}

do_turnoff_ipv6() {
   sysctl -w net.ipv6.conf.all.disable_ipv6=1
   sysctl -w net.ipv6.conf.default.disable_ipv6=1
   echo "net.ipv6.conf.all.disable_ipv6 = 1" >> /etc/sysctl.conf
   echo "net.ipv6.conf.default.disable_ipv6 = 1" >> /etc/sysctl.conf
   echo "net.ipv6.conf.lo.disable_ipv6 = 1" >> /etc/sysctl.conf
   echo "net.ipv6.conf.eth0.disable_ipv6 = 1" >> /etc/sysctl.conf
   echo "net.ipv6.conf.eth1.disable_ipv6 = 1" >> /etc/sysctl.conf
   echo "net.ipv6.conf.wlan0.disable_ipv6 = 1" >> /etc/sysctl.conf
   sysctl -p
}

# List WiFi interface
list_wlan_interfaces() {
  for dir in /sys/class/net/*/wireless; do
    if [ -d "$dir" ]; then
      basename "$(dirname "$dir")"
    fi
  done
}

# WiFi Network configuration
do_wifi_setup() {
   RET=0
   IFACE_LIST="$(list_wlan_interfaces)"
   IFACE="$(echo "$IFACE_LIST" | head -n 1)"

   # Make sure we have a wireless interface
   if [ -z "$IFACE" ]; then
     if [ "$INTERACTIVE" = True ]; then
       whiptail --msgbox "No wireless interface found" 20 60
     fi
     return 1
   fi
  
   # Confirm we can talk to the WiFi adpater
   if ! wpa_cli -i "$IFACE" status > /dev/null 2>&1; then
      if [ "$INTERACTIVE" = True ]; then
         whiptail --msgbox "Could not communicate with wpa_supplicant" 20 60
      fi
      return 1
   fi
   
   # Get Wireless network information from the user
   WPA2_ENT=False
   SSID=$(whiptail --title "Campus WiFi Setup" --inputbox "Enter SSID for wireless network" 20 60 3>&1 1>&2 2>&3)
   if (whiptail --title "Campus WiFi Setup" --yesno "Do you need a username to login to the network?" 20 60 2) then
      WPA2_ENT=True
      WPA_USERNAME=$(whiptail --title "Campus WiFi Setup" --inputbox "Enter username (if required)" 20 60 3>&1 1>&2 2>&3)
   fi
   
   WPA_PASSWORD=$(whiptail --title "Campus WiFi Setup" --inputbox "Enter password" 20 60 3>&1 1>&2 2>&3)
   
   # Cleanup the SSID with special characters
   local SSID="$(echo "$SSID" \
   | sed 's;\\;\\\\;g' \
   | sed -e 's;\.;\\\.;g' \
         -e 's;\*;\\\*;g' \
         -e 's;\+;\\\+;g' \
         -e 's;\?;\\\?;g' \
         -e 's;\^;\\\^;g' \
         -e 's;\$;\\\$;g' \
         -e 's;\/;\\\/;g' \
         -e 's;\[;\\\[;g' \
         -e 's;\];\\\];g' \
         -e 's;{;\\{;g'   \
         -e 's;};\\};g'   \
         -e 's;(;\\(;g'   \
         -e 's;);\\);g'   \
         -e 's;";\\\\\";g')"
		 
   # Remove all other wireless network configurations
   wpa_cli -i "$IFACE" list_networks \
      | tail -n +2 | cut -f -2 | grep -P "\t$ssid$" | cut -f1 \
      | while read ID; do
         wpa_cli -i "$IFACE" remove_network "$ID" > /dev/null 2>&1
      done

  # Add the wireless network to the WPA_SUPPLICANT configuration
  ID="$(wpa_cli -i "$IFACE" add_network)"
  wpa_cli -i "$IFACE" set_network "$ID" ssid "\"$SSID\"" 2>&1 | grep -q "OK"
  RET=$((RET + $?))
  
  if [ "$WPA2_ENT" = True ]; then
     # Configure for 802.1x Network Credentials
	 wpa_cli -i "$IFACE" set_network "$ID" scan_ssid "1"  2>&1 | grep -q "OK"
     wpa_cli -i "$IFACE" set_network "$ID" key_mgmt "WPA-EAP" 2>&1 | grep -q "OK"
     wpa_cli -i "$IFACE" set_network "$ID" eap "PEAP" 2>&1 | grep -q "OK"
     wpa_cli -i "$IFACE" set_network "$ID" identity "\"$WPA_USERNAME\"" 2>&1 | grep -q "OK"
     wpa_cli -i "$IFACE" set_network "$ID" password "\"$WPA_PASSWORD\"" 2>&1 | grep -q "OK"
     wpa_cli -i "$IFACE" set_network "$ID" phase1 "\"peaplabel=0\""  2>&1 | grep -q "OK"
     wpa_cli -i "$IFACE" set_network "$ID" phase2 "\"auth=MSCHAPV2\""  2>&1 | grep -q "OK"
  else
     # Configure for WPA/WPA2 PSK
     if [ -z "$WPA_PASSWORD" ]; then
        wpa_cli -i "$IFACE" set_network "$ID" key_mgmt NONE 2>&1 | grep -q "OK"
        RET=$((RET + $?))
     else
        wpa_cli -i "$IFACE" set_network "$ID" psk "\"$WPA_PASSWORD\"" 2>&1 | grep -q "OK"
        RET=$((RET + $?))
     fi
  fi 

  # Enable the WLAN interface with the new configuration
  if [ $RET -eq 0 ]; then
     wpa_cli -i "$IFACE" enable_network "$ID" > /dev/null 2>&1
  else
     wpa_cli -i "$IFACE" remove_network "$ID" > /dev/null 2>&1
     if [ "$INTERACTIVE" = True ]; then
        whiptail --msgbox "Failed to set SSID or passphrase" 20 60
     fi
  fi
  
  wpa_cli -i "$IFACE" save_config > /dev/null 2>&1

  echo "$IFACE_LIST" | while read IFACE; do
     wpa_cli -i "$IFACE" reconfigure > /dev/null 2>&1
  done

  return $RET  
}

set_local_hostname(){
    # set_hostname HOSTNAME DOMAINNAME
    echo "$1" > $HOSTNAME_FILE

    echo "127.0.0.1       localhost" > $HOSTS_FILE
    echo "127.0.1.1       $1.$2     $1" >> $HOSTS_FILE
    echo "::1             localhost ip6-localhost ip6-loopback" >> $HOSTS_FILE
    echo "ff02::1         ip6-allnodes" >> $HOSTS_FILE
    echo "ff02::2         ip6-allrouters" >> $HOSTS_FILE
}

set_eth1_dhcp() {
echo "auto eth1" >> $INTERFACES_FILE
echo "allow-hotplug eth1" >> $INTERFACES_FILE
echo "iface eth1 inet dhcp" >> $INTERFACES_FILE
echo ""  >> $INTERFACES_FILE
}

set_eth1_static_net(){
   # set_static_net IP SUBNET GATEWAY
   echo ""  >> $INTERFACES_FILE
   echo "auto eth1" >> $INTERFACES_FILE
   echo "iface eth1 inet static" >> $INTERFACES_FILE
   echo "  address $1" >> $INTERFACES_FILE
   echo "  netmask $2" >> $INTERFACES_FILE
   echo "  gateway $3" >> $INTERFACES_FILE   
   echo "  dns-nameserver $5" >> $INTERFACES_FILE   
   echo "  dns-search $4" >> $INTERFACES_FILE      
   echo "domain $5" > $DNS_FILE
   echo "nameserver $4" >> $DNS_FILE
   
   # Exclude eth1 from DHCPCD_FILE
   
   #sed -i -e '/denyinterfaces eth0/denyinterfaces eth0,eth1/g' $DHCPCD_FILE
}


# Setup eth1
do_net_setup() {
   if ( whiptail --title "Campus Network Setup" --yesno "Use DHCP?" 18 78 3>&1 1>&2 2>&3 ) then
      set_eth1_dhcp
   else
      while [ -z $RET ] || [ $RET == "1" ] ; do
        while [[ -z $IP_RESULT ]] || [[ $IP_RESULT == "1" ]] ; do
            ETH1_IPADDR=$(whiptail --title "Campus Network Setup" --inputbox "IP Address\nex: 128.45.234.3" 10 60 3>&1 1>&2 2>&3)
            if ! [[ $ETH1_IPADDR =~ $IP4 ]]; then
                whiptail --msgbox "Invalid IP!" 10 60
                ! true
            fi
            IP_RESULT=$?
        done

        ETH1_NETMASK=$(whiptail --backtitle "Campus Network Setup" --backtitle "Campus Network Setup" --inputbox "Network Mask" 10 60 "255.255.240.0" 3>&1 1>&2 2>&3)
        ETH1_GATEWAY=$(whiptail --backtitle "Campus Network Setup" --inputbox "Gateway" 10 60  3>&1 1>&2 2>&3)
        DNS1=$(whiptail --backtitle "Campus Network Setup" --inputbox "DNS" 10 60  3>&1 1>&2 2>&3)
        DOMAIN=$(whiptail --backtitle "Campus Network Setup" --inputbox "Domain Name" 10 60 "pitt.edu" 3>&1 1>&2 2>&3)
        whiptail --backtitle "Campus Network Setup" --title "Are the settings correct?" --yesno "\n IP Adress: $ETH1_IPADDR \n Netmask: $ETH1_NETMASK \n Gateway: $ETH1_GATEWAY \n DNS: $DNS1 \n Domain: $DOMAIN \n" 18 78 3>&1 1>&2 2>&3
        RET=$?
      done
	  
	  set_eth1_static_net "$ETH1_IPADDR" "$ETH1_NETMASK" "$ETH1_GATEWAY" "$DNS1" "$DOMAIN"
	  
   fi
   
   set_local_hostname
}

# Reload the network
do_restart_network() {

   # disable the dhcp client
   systemctl stop dhcpcd.service
   systemctl disable dhcpcd.service

   # Flush the network address so it will reconfig properly
   ip addr flush eth0
   ip addr flush eth1
   ip addr flush wlan0

   # Kill the wpa-supplicant, not sure if this is really needed.
   if [ -x /var/run/wpa_supplicant/wlan0 ]; then
      wpa_cli reconfigure 3>&1 1>&2 2>&3
      rm /var/run/wpa_supplicant/wlan0
      killall wpa_supplicant
   fi

   if [ -e /etc/resolv.conf.dmz ]; then
      cp /etc/resolv.conf.dmz /etc/resolv.conf
   fi

   systemctl daemon-reload
   systemctl restart networking.service

   if [ -e /etc/resolv.conf.dmz ]; then
      cp /etc/resolv.conf.dmz /etc/resolv.conf
   fi

   # Make sure all the network interfaces are started
   ifup eth0 3>&1 1>&2 2>&3
   ifup eth1 3>&1 1>&2 2>&3
   ifup wlan0 3>&1 1>&2 2>&3
}

# Update apt catalog
do_apt_update() {
   apt-get update
   apt-get -y upgrade
   apt-get -y dist-upgrade
}

do_install_dhcp_server() {
	apt-get -y install isc-dhcp-server 
}

do_configure_dhcp_server() {
   # Add the configuration for the instrumentation network
   echo "subnet 192.168.0.0 netmask 255.255.255.0 {"  >> $DHCPD_FILE
   echo "range 192.168.0.10 192.168.0.10;" >> $DHCPD_FILE
   echo "option broadcast-address 192.168.0.255;" >> $DHCPD_FILE
   echo "}" >> $DHCPD_FILE
   
   # Only start IPv4 server
   sed -i -e 's/v4=""/v4="eth0"/g' /etc/default/isc-dhcp-server
}

do_install_guacamnole() {
   # apt-get install software-properties-common python-software-properties
   # add-apt-repository ppa:guacamole/stable
   # apt-get update
   
   apt-get -y install guacamole
   apt-get -y install libguac-client-ssh0 libguac-client-rdp0
   
   chkconfig tomcat6 on
   chkconfig guacd on
   
   service tomcat6 start
   service guacd start
 
}

do_guac_rdp (){
   echo "Configuring guacamole for RDP"
}

do_guac_vnc (){
   echo "Configuring guacamole for VNC"
}

do_guac_ssh (){
   echo "Configuring guacamole for ssh"
}

do_guac_serial (){
   echo "Configuring guacamole for serial connection"
   echo "hahaha - not yet."
}

do_suth_setup_local() {
   echo "Not yet written"
}

do_auth_setup_kerberos() {
   echo "Not yet written"
}

do_auth_setup_shib() {
   echo "Not yet written"
}

do_auth_setup_cas() {
   echo "Not yet written"
}

do_auth_setup_openid() {
   echo "Not yet written"
}
