#!/bin/bash

clear

WORK_DIR=$(pwd)

##############################################################
# Define ANSI escape sequence for green, red and yellow font #
##############################################################

GREEN='\033[0;32m'
RED='\033[0;31m'
YELLOW='\033[0;33m'


########################################################
# Define ANSI escape sequence to reset font to default #
########################################################

NC='\033[0m'


#################
# Intro message #
#################

echo
echo -e "${GREEN} This script will install and configure Unbound DNS and, optionaly, Pi-Hole Add blocker ${NC}"

sleep 0.5 # delay for 0.5 seconds
echo

echo -e "${GREEN} You'll be asked to enter: ${NC}"
echo -e " - One Local Subnet for Access Control"
echo -e " - One entry for Local DNS Lookup (hostname/ip)"
echo
echo -e "${GREEN} If you opt to install Pi-Hole, you'll be asked to enter:${NC}"
echo -e " - Pi-Hole Dashboard Admin Password"
echo


######################################
# Prompt user to confirm script start#
######################################

while true; do
    echo -e "${GREEN} Start installation and configuration?${NC} (yes/no) "
    echo
    read choice
    echo
    choice=$(echo "$choice" | tr '[:upper:]' '[:lower:]') # Convert input to lowercase

    # Check if user entered "yes"
    if [[ "$choice" == "yes" ]]; then
        # Confirming the start of the script
        echo
        echo -e "${GREEN} Starting... ${NC}"
        sleep 0.5 # delay for 0.5 second
        echo
        break

    # Check if user entered "no"
    elif [[ "$choice" == "no" ]]; then
        echo -e "${RED} Aborting script. ${NC}"
        exit

    # If user entered anything else, ask them to correct it
    else
        echo -e "${YELLOW} Invalid input. Please enter${NC} 'yes' or 'no'"
        echo
    fi
done


###################
# Install Unbound #
###################

echo -e "${GREEN} Installing Unbound and other packages ${NC}"

sleep 0.5 # delay for 0.5 seconds
echo

if ! sudo apt -y install unbound net-tools tcpdump ca-certificates; then
    echo -e "${RED} Failed to install packages. Exiting.${NC}"
    exit 1
fi


#######################
# Create backup files #
#######################

echo
echo -e "${GREEN} Creating backup files ${NC}"

sleep 0.5 # delay for 0.5 seconds
echo

# Backup the existing /etc/hosts file
if [ ! -f /etc/hosts.backup ]; then
    sudo cp /etc/hosts /etc/hosts.backup
    echo -e "${GREEN} Backup of${NC} /etc/hosts ${GREEN}created.${NC}"
else
    echo -e "${YELLOW} Backup of${NC} /etc/hosts ${YELLOW}already exists. Skipping backup.${NC}"
fi

# Backup original /etc/cloud/cloud.cfg file before modifications
CLOUD_CFG="/etc/cloud/cloud.cfg"
if [ ! -f "$CLOUD_CFG.bak" ]; then
    sudo cp "$CLOUD_CFG" "$CLOUD_CFG.bak"
    echo -e "${GREEN} Backup of${NC} $CLOUD_CFG ${GREEN}created.${NC}"
else
    echo -e "${YELLOW} Backup of${NC} $CLOUD_CFG ${YELLOW}already exists. Skipping backup.${NC}"
fi

# Before modifying Unbound configuration files, create backups if they don't already exist

UNBOUND_FILES=(
    "/etc/unbound/unbound.conf"
)

for file in "${UNBOUND_FILES[@]}"; do
    if [ ! -f "$file.backup" ]; then
        sudo cp "$file" "$file.backup"
        echo -e "${GREEN} Backup of${NC} $file ${GREEN}created.${NC}"
    else
        echo -e "${YELLOW} Backup of${NC} $file ${YELLOW}already exists. Skipping backup.${NC}"
    fi
done


#######################
# Edit cloud.cfg file #
#######################

echo
echo -e "${GREEN} Preventing Cloud-init of rewritining hosts file ${NC}"

sleep 0.5 # delay for 0.5 seconds
echo

# Define the file path
FILE_PATH="/etc/cloud/cloud.cfg"

# Comment out the specified modules
sudo sed -i '/^\s*- set_hostname/ s/^/#/' "$FILE_PATH"
sudo sed -i '/^\s*- update_hostname/ s/^/#/' "$FILE_PATH"
sudo sed -i '/^\s*- update_etc_hosts/ s/^/#/' "$FILE_PATH"

echo -e "${GREEN} Modifications to${NC} $FILE_PATH ${GREEN}applied successfully.${NC}"


######################
# Prepare hosts file #
######################

echo
echo -e "${GREEN} Setting up hosts file ${NC}"

sleep 0.5 # delay for 0.5 seconds
echo

# Extract the domain name from /etc/resolv.conf
domain_name=$(awk -F' ' '/^domain/ {print $2; exit}' /etc/resolv.conf)

# Get the host's IP address and hostname
host_ip=$(hostname -I | awk '{print $1}')
host_name=$(hostname)

# Construct the new line for /etc/hosts
new_line="$host_ip $host_name $host_name.$domain_name"

# Create a temporary file with the desired contents
{
    echo "# Your system has configured 'manage_etc_hosts' as True."
    echo "# As a result, if you wish for changes to this file to persist"
    echo "# then you will need to either"
    echo "# a.) make changes to the master file in /etc/cloud/templates/hosts.debian.tmpl"
    echo "# b.) change or remove the value of 'manage_etc_hosts' in"
    echo "# /etc/cloud/cloud.cfg or cloud-config from user-data"
    echo ""
    echo "$new_line"
    echo "============================================"
    # Replace the line containing the current hostname with the new line
    awk -v hostname="$host_name" -v new_line="$new_line" '!($0 ~ hostname) || $0 == new_line' /etc/hosts
} > /tmp/hosts.tmp

# Move the temporary file to /etc/hosts
sudo mv /tmp/hosts.tmp /etc/hosts

echo -e "${GREEN} File${NC} /etc/hosts ${GREEN}has been updated ${NC}"


####################
# Prepare firewall #
####################

echo
echo -e "${GREEN} Preparing firewall ${NC}"

sleep 0.5 # delay for 0.5 seconds
echo

sudo ufw allow 53/udp comment "DNS port 53/udp" && \
sudo ufw allow 53/tcp comment "DNS port 53/tcp" && \
sudo ufw allow 853/tcp comment "DNS over TLS port 853/tcp" && \
sudo systemctl restart ufw


#####################
# Update root hints #
#####################

echo
echo -e "${GREEN} Updating root hints file ${NC}"

sleep 0.5 # delay for 0.5 seconds
echo

wget https://www.internic.net/domain/named.root -qO- | sudo tee /usr/share/dns/root.hints
echo


##############################
# Improve avg response times #
##############################

echo
echo -e "${GREEN} Adding options to sysctl.conf file ${NC}"

sleep 0.5 # delay for 0.5 seconds
echo

echo "net.core.rmem_max=8388608" | sudo tee -a /etc/sysctl.conf > /dev/null && sudo sysctl -p


#############################
# Modify dhclient.conf file #
#############################

echo
echo -e "${GREEN} Preventing${NC} dhclient ${GREEN}from overwriting${NC} resolve.conf"

sleep 0.5 # delay for 0.5 seconds
echo

# Path to the dhclient.conf file
DHCLIENT_CONF="/etc/dhcp/dhclient.conf"

# Check if the dhclient.conf file exists
if [ ! -f "$DHCLIENT_CONF" ]; then
    echo -e "${RED} Error:${NC} $DHCLIENT_CONF ${RED}does not exist. ${NC}"
    exit 1
fi

# Backup the original file before making changes
sudo cp $DHCLIENT_CONF "${DHCLIENT_CONF}.bak"
if [ $? -ne 0 ]; then
    echo -e "${RED} Error: Failed to backup the original${NC} dhclient.conf ${RED}file. ${NC}"
    exit 1
fi

# Replace the specified lines
sudo sed -i 's/domain-name, domain-name-servers, domain-search, host-name,/domain-name, domain-search, host-name,/' $DHCLIENT_CONF
if [ $? -ne 0 ]; then
    echo -e "${RED} Error: Failed to replace the first specified line. ${NC}"
    exit 1
fi

sudo sed -i 's/dhcp6.name-servers, dhcp6.domain-search, dhcp6.fqdn, dhcp6.sntp-servers,/dhcp6.domain-search, dhcp6.fqdn, dhcp6.sntp-servers,/' $DHCLIENT_CONF
if [ $? -ne 0 ]; then
    echo -e "${RED} Error: Failed to replace the second specified line. ${NC}"
    exit 1
fi

# Get the primary IP address of the machine
IP_ADDRESS=$(hostname -I | awk '{print $1}')
if [ -z "$IP_ADDRESS" ]; then
    echo -e "${RED} Error: Failed to obtain the IP address of the machine. ${NC}"
    exit 1
fi

# Check and replace the "prepend domain-name-servers" line with the machine's IP address
sudo sed -i "/^#prepend domain-name-servers 127.0.0.1;/a prepend domain-name-servers ${IP_ADDRESS};" $DHCLIENT_CONF
if [ $? -ne 0 ]; then
    echo -e "${RED} Error: Failed to insert the machine's IP address. ${NC}"
    exit 1
fi

# Now, find the line with the machine's IP address and add the 127.0.0.1 below it
sudo sed -i "/^prepend domain-name-servers ${IP_ADDRESS};/a prepend domain-name-servers 127.0.0.1;" $DHCLIENT_CONF
if [ $? -ne 0 ]; then
    echo -e "${RED} Error: Failed to insert the${NC} 127.0.0.1 ${RED}address below the machine's IP address. ${NC}"
    exit 1
fi

echo -e "${GREEN} Modifications completed successfully. ${NC}"


########################################
# Preparing Unbound configuration file #
########################################

echo
echo -e "${GREEN} Preparing Unbound configuration file:${NC} unbound.conf"

sleep 0.5 # delay for 0.5 seconds
echo

# Extract the domain name from /etc/resolv.conf
DOMAIN_NAME_LOCAL=$(grep '^domain' /etc/resolv.conf | awk '{print $2}')

# Check if the domain name was found
if [ -z "$DOMAIN_NAME_LOCAL" ]; then
  echo -e "${RED} Domain name not found in ${NC} /etc/resolv.conf"
  exit 1
fi

# Replace DOMAIN_NAME placeholder in unbound.conf with the extracted domain name
sed -i "s/DOMAIN_NAME_LOCAL/$DOMAIN_NAME_LOCAL/g" unbound.conf

echo -e "${GREEN} Domain name${NC} $DOMAIN_NAME_LOCAL ${GREEN}has been set in${NC} unbound.conf"
echo
# User input

num_lines=$(tput lines)
echo -e "\033[${num_lines}A\033[0J"

# Ask and validate LOCAL_SUBNET_ACCESS
while true; do
  echo
  read -p "Enter Local Subnet for Access Control (Format example: 192.168.10.0/24): " LOCAL_SUBNET_ACCESS
  if echo "$LOCAL_SUBNET_ACCESS" | grep -Eq '^[0-9]+\.[0-9]+\.[0-9]+\.[0-9]+/[0-9]+$'; then
    break
  else
    echo -e "${RED} Error: Subnet format is invalid. Please enter a valid${NC} CIDR ${RED}notation. ${NC}"
  fi
done

# Ask and validate HOST_NAME_LOCAL
while true; do
  echo
  read -p "Enter Machine Host Name (Format example: server01): " HOST_NAME_LOCAL
  if echo "$HOST_NAME_LOCAL" | grep -Eq '^[a-zA-Z0-9\-]+$'; then
    break
  else
    echo -e "${RED} Error: Host name format is invalid. Use only alphanumeric characters and hyphens. ${NC}"
  fi
done

# Ask and validate IP_LOCAL
while true; do
  echo
  read -p "Enter IP address for the Host you have named (Format example: 192.168.1.11): " IP_LOCAL
  if echo "$IP_LOCAL" | grep -Eq '^[0-9]+\.[0-9]+\.[0-9]+\.[0-9]+$'; then
    break
  else
    echo -e "${RED} Error: IP Address format is invalid. Please enter a valid${NC} IPv4 ${RED}address. ${NC}"
  fi
done

echo

sed -i "s/DOMAIN_NAME_LOCAL/$DOMAIN_NAME_LOCAL/g" unbound.conf

sleep 0.5 # delay for 0.5 seconds

# Attempt to replace placeholders in unbound.conf
if sed -i "s:LOCAL_SUBNET_ACCESS:$LOCAL_SUBNET_ACCESS:g" unbound.conf; then
  echo -e "${GREEN} Local Subnet applied successfully. ${NC}"
else
  echo -e "${RED} Error replacing Subnet Address. ${NC}"
  exit 1
fi

if sed -i "s:HOST_NAME_LOCAL:$HOST_NAME_LOCAL:g" unbound.conf; then
  echo -e "${GREEN} Host name applied successfully. ${NC}"
else
  echo -e "${RED} Error replacing Host Name. ${NC}"
  exit 1
fi

if sed -i "s:IP_LOCAL:$IP_LOCAL:g" unbound.conf; then
  echo -e "${GREEN} IP Address applied successfully."
else
  echo -e "${RED} Error replacing IP Address. ${NC}"
  exit 1
fi

echo -e "${GREEN} Configuration file updated successfully. ${NC}"
echo

sleep 0.5 # delay for 0.5 seconds


#############################
# Option to install Pi-Hole #
#############################

# Function to ask the user if they want to Install Pi-Hole
ask_to_execute_commands() {
    while true; do
        # Prompt the user
        read -p "Do you want to install Pi-Hole alongside Unbound? (yes/no): " answer
        echo
        # Normalize the answer to lower case
        case "${answer,,}" in
            yes|y)
                echo -e "${GREEN} Preconfiguring and installing Pi-Hole...${NC}"
                echo


                #######################################################
                # Install necesary package and perform hw clock check #
                #######################################################
                
                sudo apt install expect -y
                sudo hwclock --hctosys


                ##############################
                # Create setupVars.conf file #
                ##############################
                
                # Define the path to the directory and the file
                directory_path=$(cd "$(dirname "${BASH_SOURCE[0]}")" &> /dev/null && pwd)
                file_path="$directory_path/setupVars.conf"

                # Create or overwrite the setupVars.conf file, using sudo for permissions
                echo
                echo -e "${GREEN} Creating file:${NC} $file_path"

                sudo tee "$file_path" > /dev/null <<EOF
PIHOLE_INTERFACE=NET_INT
QUERY_LOGGING=true
INSTALL_WEB_SERVER=true
INSTALL_WEB_INTERFACE=true
LIGHTTPD_ENABLED=true
CACHE_SIZE=10000
DNS_FQDN_REQUIRED=true
DNS_BOGUS_PRIV=true
DNSMASQ_LISTENING=single
WEBPASSWORD=SHA-256
BLOCKING_ENABLED=true
DNSSEC=false
REV_SERVER=false
PIHOLE_DNS_1=127.0.0.1#5335
PIHOLE_DNS_2=
EOF
                echo
                echo -e "${GREEN} File${NC} setupVars.conf ${GREEN}created successfully.${NC}"
                echo


                #################################################################################
                # replace SHA-256 hash placeholder with User defined Password in setupVars.conf #
                #################################################################################
                
                # Path to the configuration file
                config_file="setupVars.conf"

                # Function to generate double SHA-256 hash
                generate_double_sha256_hash() {
                    # First SHA-256 hash
                    local hashed_pw=$(echo -n "$1" | sha256sum | sed 's/\s.*$//')

                    # Second SHA-256 hash
                    local double_hashed_pw=$(echo -n "${hashed_pw}" | sha256sum | sed 's/\s.*$//')

                    echo "${double_hashed_pw}" # Return the double hashed password
                }

                # Function to replace the placeholder in the configuration file
                replace_placeholder() {
                    local hash=$1
                    sed -i "s/SHA-256/$hash/" "$config_file" || echo -e "${RED} Error: Failed to replace the placeholder in $config_file${NC}" >&2
                }

                num_lines=$(tput lines)
                echo -e "\033[${num_lines}A\033[0J"

                # Loop until a valid password is entered
                while true; do
                    # Prompt the user for a password
                    echo
                    echo -e "${GREEN} Please enter the Pi-Hole Web Admin Password (min 6 characters):${NC}"
                    echo
                    read -s -p "Password: " user_password

                    # Check if the password is empty
                    if [ -z "$user_password" ]; then
                        echo -e "${RED}: No password entered. Please try again.${NC}"
                        echo
                        continue
                    fi

                    # Check if the password length is less than 6 characters
                    if [ ${#user_password} -lt 6 ]; then
                        echo -e "${RED} Error: Password must be at least 6 characters long. Please try again.${NC}"
                        echo
                        continue
                    fi

                    # Save user Web Admin Console Password in case you forgot
                    echo "$user_password" > "webadmin_password.txt" 

                    # Password meets the requirements; generate double hash
                    hash=$(generate_double_sha256_hash "$user_password")

                    # Save Password Hash for debugging 
                    echo
                    echo "$hash" > "webadmin_password_hash.txt"
                    echo

                    # Replace the placeholder in the configuration file
                    replace_placeholder "$hash"
                    break # Exit the loop after successful operation
                done


                ###############################################################################
                # replace NET_INT placeholder with primary network interfac in setupVars.conf #
                ###############################################################################
                
                # Path to the configuration file
                config_file="setupVars.conf"

                # Function to identify the primary network interface
                identify_network_interface() {
                    # This command finds the primary network interface used for the default route
                    ip route | grep default | awk '{print $5}' | head -n 1
                }

                # Function to replace the placeholder in the configuration file
                replace_placeholder() {
                    local net_interface=$1
                    sed -i "s/NET_INT/$net_interface/" "$config_file" || echo -e "${RED} Error: Failed to replace the placeholder in $config_file ${NC}" >&2
                }

                # Identify the network interface
                network_interface=$(identify_network_interface)

                if [ -n "$network_interface" ]; then
                    echo -e "${GREEN} Primary network interface identified:${NC} $network_interface"
                    echo
                    # Replace the placeholder in the configuration file
                    replace_placeholder "$network_interface"
                else
                    echo -e "${RED} Error: Failed to identify the primary network interface ${NC}" >&2
                fi


                ################################
                # Set Pi-Hole automatic update #
                ################################
                
                # Set Pi-Hole automatic update cron jobs
                JOB1="# Pi-Hole automatic update"
                JOB2="0 2 1 * * pihole -up"
                JOB3="0 3 1 * * pihole -g"

                for job in "$JOB1" "$JOB2" "$JOB3"; do
                    if (crontab -l 2>/dev/null; echo "$job") | crontab -; then
                        echo -e "${GREEN} Job added to${NC} crontab"
                    else
                        echo -e "${RED} Error: Unable to append job to${NC} crontab"
                    fi
                done

                echo
                

                #####################################
                # Copy prepared setupVars.conf file #
                #####################################
                
                # Attempt to create the directory
                sudo mkdir -p /etc/pihole
                if [ $? -eq 0 ]; then
                    echo -e "${GREEN} Directory${NC} /etc/pihole ${GREEN}created or already exists.${NC}"
                else
                    echo -e "${RED} Failed to create${NC} /etc/pihole ${RED}directory.${NC}"
                    exit 1
                fi

                # Attempt to copy the file
                sudo cp setupVars.conf /etc/pihole/setupVars.conf
                if [ $? -eq 0 ]; then
                    echo
                    echo -e "${GREEN} File copied successfully.${NC}"
                else
                    echo -e "${RED} Failed to copy file.${NC}"
                    exit 1
                fi


                ###########################################
                # Adjust the port nummber in unbound.conf #
                ###########################################
                
                echo
                echo -e "${GREEN} Adjusting Unbound port for Pi-Hole.${NC}"

                sleep 0.5 # delay for 0.5 seconds
                echo

                if sudo sed -i 's/port: 53/port: 5335/' unbound.conf; then
                    echo -e "${GREEN} Configuration update successfully applied to${NC} unbound.conf"
                else
                    echo -e "${RED} Error: Failed to update configuration in${NC} unbound.conf"
                fi


                ####################
                # Prepare Firewall #
                ####################
                
                echo
                echo -e "${GREEN} Preparing firewall for${NC} Pi-Hole Admin Console "

                sleep 0.5 # delay for 0.5 seconds
                echo

                sudo ufw allow 80/tcp comment 'Pi-Hole Admin Console'
                sudo systemctl restart ufw
                echo


                ##############################
                # Run Pi-Hole install Script #
                ##############################
                
                # Script is executable and has a shebang line
                ./pihole-install.sh

                # Check the exit status of the last command
                if [ $? -eq 0 ]; then
                    echo
                    echo -e "${GREEN} Pi-Hole installation completed successfully.${NC}"
                else
                    echo -e "${RED} Pi-Hole installation encountered an error.${NC}"
                fi

                echo
                # ...
                break # Exit the loop after executing the commands
                ;;
            no|n)
                echo -e "${YELLOW} Skipping Pi-Hole installation${NC}"
                break # Exit the loop and continue with the rest of the script
                ;;
            *)
                echo -e "${RED} Error: Please answer${NC} 'yes' or 'no' "
                echo
                ;;
        esac
    done
}

# Call the function
ask_to_execute_commands


##############################
# Replace configuration file #
##############################

echo -e "${GREEN} Replacing existing Unbound configuration file.${NC}"

sleep 0.5 # delay for 0.5 seconds
echo

if sudo cp unbound.conf /etc/unbound/unbound.conf; then
    echo -e "${GREEN} File${NC} unbound.conf ${GREEN}copied successfully. ${NC}"
    echo
else
    echo -e "${RED} Error: Failed to copy file${NC} unbound.conf ${RED}to${NC} /etc/unbound/ ${NC}"
fi


###############################
# Root hints automatic update #
###############################

# Define the command to execute
command="wget https://www.internic.net/domain/named.root -qO- | sudo tee /usr/share/dns/root.hints > /dev/null && sudo systemctl restart unbound"

# The crontab entry will perform the following tasks:
# 1. Download the latest root hints file from https://www.internic.net/domain/named.root
# 2. Save the downloaded file as /usr/share/dns/root.hints (requires sudo permissions)
# 3. Restart the unbound DNS resolver service (requires sudo permissions)
#
# The cron job will run at 00:00 (midnight) on the first day of every third month.
# This means the root hints file will be updated and the unbound service restarted
# every 3 months to ensure the system has the latest root DNS server information.
cron_entry="0 0 1 */3 * $command"
cron_comment="# Update root hints and restart unbound DNS resolver"

# Function to check if the cron entry is already present
check_crontab() {
    crontab -l | grep -Fxq "$cron_entry"
}

# Function to update the crontab
update_crontab() {
    temp_file=$(mktemp)
    crontab -l > "$temp_file"
    echo "$cron_comment" >> "$temp_file"
    echo "$cron_entry" >> "$temp_file"
    crontab "$temp_file"
    rm "$temp_file"
}

# Check if the cron entry is already present
if check_crontab; then
    echo -e "${YELLOW} Cron entry already exists in the crontab.${NC}"
else
    echo -e "${GREEN} Adding cron entry to the${NC} crontab"
    update_crontab || { echo -e "${RED} Failed to update the crontab.${NC}"; exit 1; }
fi

echo
echo -e "${GREEN} Crontab updated successfully.${NC}"
sleep 0.5 # delay for 0.5 seconds


######################
# Info before reboot #
######################

num_lines=$(tput lines)
echo -e "\033[${num_lines}A\033[0J"

domain_name=$(awk -F' ' '/^domain/ {print $2; exit}' /etc/resolv.conf)
IP_ADDRESS=$(hostname -I | awk '{print $1}')
host_name=$(hostname)
pi_hole="http://$host_name.$domain_name/admin"

echo
echo -e "${GREEN}REMEMBER: ${NC}"
echo
echo
echo -e "${GREEN} - Unbound will listen on${NC} all interfaces${GREEN}, with access limited to one Subnet:${NC} $LOCAL_SUBNET_ACCESS"
echo
echo -e "${GREEN} - Access limited to one Subnet:${NC} $LOCAL_SUBNET_ACCESS"
echo
echo -e "${GREEN} - One Local A Record defined:${NC} $HOST_NAME_LOCAL"
echo
echo -e "${GREEN}   to continue configuring edit:${NC} /etc/unboun/unboud.conf"
echo
echo -e "${GREEN} - Queries that cannot be answered locally Unbound will forward to${NC} Upstream DNS servers,"
echo
echo -e "${GREEN}   using${NC} DNS-over-TLS (DoT) ${GREEN}for encryption, enhancing privacy and security ${NC}"
echo
echo -e "${GREEN} - Forwarders:${NC} Quad9${GREEN},${NC} Cloudflare${GREEN}, and optionally${NC} Google ${GREEN}(must be enabled) ${NC}"
echo
echo -e "${GREEN}   If Forwarder are disabled, Unbound will operate as a${NC} Recursive DNS Resolver"
echo
echo -e "${GREEN}   This aproach will prioritize privacy, security, and independence from third-party DNS services${NC}"
echo
echo -e "${GREEN} - If you have opted for installing${NC} Pi-Hole"
echo
echo -e "${GREEN}   it will act as a network-wide ad blocker, using Unbound in the background  ${NC}"
echo
echo -e "${GREEN} - Point your Subnets or individual Clients to${NC} Pi-Hole ${GREEN}IP Address:${NC} $IP_ADDRESS"
echo
echo -e "${GREEN} - Pi-hole Dashboard can be found at:${NC} http://$IP_ADDRESS/admin ${GREEN}or,${NC}"
echo
echo -e "${GREEN}   If Local A Record (Unbound) is properly configured, at:${NC} $pi_hole"
echo
echo


##########################
# Prompt user for reboot #
##########################

while true; do
    read -p "Do you want to reboot the server now (recommended)? (yes/no): " response
    echo
    case "${response,,}" in
        yes|y) echo -e "${GREEN} Rebooting the server...${NC}"; sudo reboot; break ;;
        no|n) echo -e "${RED} Reboot cancelled.${NC}"; exit 0 ;;
        *) echo -e "${YELLOW} Invalid response. Please answer${NC} yes or no."; echo ;;
    esac
done


####################################
# Remove Script(s) from the system #
####################################

echo
echo -e "${RED} This Script Will Self Destruct!${NC}"
echo
cd ~
sudo rm -rf $WORK_DIR
