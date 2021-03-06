#!/bin/bash

##############################################
##
##   Mini-DMZ Setup Script
##
##   Version: 0.1
##
##   C.Keslar
##
###############################################

#
# Defaults and configuraiton
# 
INTERACTIVE=True
ASK_TO_REBOOT=0
CAMPUS_NET_WIFI=True

# System Files
HOSTNAME_FILE="/etc/hostname"
DHCPCD_FILE="/etc/dhcpcd.conf"
DHCPD_FILE="/etc/dhcp/dhcpd.conf"
HOSTS_FILE="/etc/hosts"
DNS_FILE="/etc/resolv.conf"
INTERFACES_FILE="/etc/network/interfaces"

#
#  Function Libraries
#
. $(dirname "$0")/common.sh

#
# Main Setup
#
whiptail --title "Science Mini-DMZ Device Setup" --msgbox "\
This script will install the Mini-DMZ setup. The Mini-DMZ can \
be used to provide remote console access to stranded \
scientific instruments that you would not normally be able to \
connect to your campus network.\n\n\
The stranded instrument will attach to the ethernet port \
built into the the Raspberry Pi, and the Raspberry Pi \
will connect to the campus network either thru it's \
built-in wifi adapter or a separate USB network adapter.\n\n\
If you plan on connecting the Mini-DMZ to the campus network \
through a wired ethernet connection, please plug-in the USB \
network adapter before continuing the configuration." 20 70 1


# Allow the user to set the keyboard configuration
clear
echo "Configure the keyboard setup . . ."
do_configure_keyboard

# Set the proper time zone
clear
echo "Set the time zone . . ."
do_change_timezone

# Set the hostname
clear
echo "Set the hostname . . ."
do_hostname

# Create a new user
clear
echo "Create a new user . . ."
do_newuser

# Disable user pi
clear
echo "Disable the default user pi . . ."
chsh -s /sbin/nologin pi

# Set the static IP Address for eth0
clear
echo "Set the static ip address settings for scientific instrament conneciton . . ."
do_set_eth0

# Turn off IPv6
clear
echo "Turning off IPv6 on this system . . ."
do_turnoff_ipv6

# Determine how to connect to the campus network/interfaces
# If USB ethernet adapter not installed, assume WiFi
if [ -x /sys/class/net/eth1 ]; then
   if !(whiptail --title "Campus Network Config" --yesno "Would you like to connect the the campus network wirelessly?" 20 60 2) then
      CAMPUS_NET_WIFI=False
   fi
fi

if [ "$CAMPUS_NET_WIFI" = True ]; then
   do_wifi_setup
else
   do_net_setup
fi

# Restart network to activate configuration
clear
echo "Restarting network interface . . . "
do_restart_network
echo "Network restarted."

# Update the system
clear
echo "Updating the operating system and currently installed packages . . ."
do_apt_update

# Configure the DHCP Server for Instrument network
clear
echo "Installing a DHCP server for instrument network . . ."
do_install_dhcp_server
echo "Configuring the DHCP zone for the instrument . . ."
do_configure_dhcp_server

# Dynaic DNS 
clear
echo "Installing Dynamic DNS client . . ."
if (whiptail --title "Dynamic DNS Setup" --yesno "Would you like to setup Dynamic DNS?" 20 60 2) then
	do_ddns_setup
fi

# Personar
clear
echo "Installing perfsonar node . . ."
if (whiptail --title "Install personar" --yesno "Would you like to install perfsonar test point on this device?" 20 70 5); then
	do_setup_perfsonar
fi

# Install and configure Guacamole
clear 
echo "Installing Apache/Tomcat/Guacamole . . ."
do_install_guacamnole

# Configure Guacamole
clear
echo "Configuring Guacamole server . . ."
GUAC_CONNECT_TYPE=$(whiptail --title "Connect to Instrument" --menu "How do you connect to the instrument:"  20 70 3 \
"RDP" "Windows Remote Desktop" \
"VNC" "Virtual Network Computing (VNC)" \
"SSH" "ssh terminal" 3>&1 1>&2 2>&3 )

case $GUAC_CONNECT_TYPE in
"RDP")
do_guac_rdp
;;
"VNC")
do_guac_vnc
;;
"SSH")
do_guac_ssh
;;
*)
;;
esac

# Setup authentication
clear
echo "Authentication setup would occur at this point."
AUTH_CHOICE=$(whiptail --title "Authentication Setup" --menu \
"What authentication mechanism would you like to use to control acess to this Mini-DMZ device?" 20 70 2 \
"SAML"     "SAML/Shibboleth" \
"CAS"      "Central Authenitcation Service (CAS)" 3>&1 1>&2 2>&3 )

case $AUTH_CHOICE in
"SAML")
do_auth_setup_shib
;;
"CAS")
do_auth_setup_cas
;;
esac

# The end
clear
echo "de Fini!"
reboot
