#!/bin/bash

clear

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
echo -e "${GREEN} message ${NC}"

sleep 0.5 # delay for 0.5 seconds
echo

echo -e "${GREEN}REMEMBER: ${NC}"
echo
sleep 0.5 # delay for 0.5 seconds

echo -e "${GREEN} - some text ${NC}"
echo -e "${GREEN} - some text ${NC}"
echo -e "${GREEN} - some text ${NC}"

sleep 1 # delay for 1 seconds
echo


###################
# Install Unbound #
###################
echo
echo -e "${GREEN} Installing Unbound and other packages ${NC}"

sleep 0.5 # delay for 0.5 seconds
echo

if ! sudo apt -y install unbound net-tools tcpdump ca-certificates; then
    echo "Failed to install packages. Exiting."
    exit 1
fi


#######################
# Create backup files #
#######################

echo
echo -e "${GREEN} Createing backup files ${NC}"

sleep 0.5 # delay for 0.5 seconds
echo

# Backup the existing /etc/hosts file
if [ ! -f /etc/hosts.backup ]; then
    sudo cp /etc/hosts /etc/hosts.backup
    echo -e "${GREEN}Backup of /etc/hosts created.${NC}"
else
    echo -e "${YELLOW}Backup of /etc/hosts already exists. Skipping backup.${NC}"
fi

# Backup original /etc/cloud/cloud.cfg file before modifications
CLOUD_CFG="/etc/cloud/cloud.cfg"
if [ ! -f "$CLOUD_CFG.bak" ]; then
    sudo cp "$CLOUD_CFG" "$CLOUD_CFG.bak"
    echo -e "${GREEN}Backup of $CLOUD_CFG created.${NC}"
else
    echo -e "${YELLOW}Backup of $CLOUD_CFG already exists. Skipping backup.${NC}"
fi

# Before modifying Unbound configuration files, create backups if they don't already exist

UNBOUND_FILES=(
    "/etc/unbound/unbound.conf"
)

for file in "${UNBOUND_FILES[@]}"; do
    if [ ! -f "$file.backup" ]; then
        sudo cp "$file" "$file.backup"
        echo -e "${GREEN}Backup of $file created.${NC}"
    else
        echo -e "${YELLOW}Backup of $file already exists. Skipping backup.${NC}"
    fi
done


######################
# Prepare hosts file #
######################
echo
echo -e "${GREEN} Setting up hosts file ${NC}"

sleep 0.5 # delay for 0.5 seconds
echo

# Extract the domain name from /etc/resolv.conf
DOMAIN_NAME=$(grep '^domain' /etc/resolv.conf | awk '{print $2}')

# Check if DOMAIN_NAME has a value
if [ -z "$DOMAIN_NAME" ]; then
    echo "${RED}Could not determine the domain name from /etc/resolv.conf. Skipping operations that require the domain name.${NC}"
else
    # Continue with operations that require DOMAIN_NAME
    # Identify the host's primary IP address and hostname
    HOST_IP=$(hostname -I | awk '{print $1}')
    HOST_NAME=$(hostname)

    # Skip /etc/hosts update if HOST_IP or HOST_NAME are not determined
    if [ -z "$HOST_IP" ] || [ -z "$HOST_NAME" ]; then
        echo -e "${RED}Could not determine the host IP address or hostname. Skipping /etc/hosts update${NC}"
    else
        # Display the extracted domain name, host IP, and hostname
        echo -e "${GREEN}Domain name: $DOMAIN_NAME${NC}"
        echo -e "${GREEN}Host IP: $HOST_IP${NC}"
        echo -e "${GREEN}Hostname: $HOST_NAME${NC}"

        # Remove any existing lines with the current hostname in /etc/hosts
        sudo sed -i "/$HOST_NAME/d" /etc/hosts

        # Prepare the new line in the specified format
        NEW_LINE="$HOST_IP\t$HOST_NAME $HOST_NAME.$DOMAIN_NAME"

        # Insert the new line directly below the 127.0.0.1 localhost line
        sudo awk -v newline="$NEW_LINE" '/^127.0.0.1 localhost$/ { print; print newline; next }1' /etc/hosts | sudo tee /etc/hosts.tmp > /dev/null && sudo mv /etc/hosts.tmp /etc/hosts

        echo -e "${GREEN}File /etc/hosts has been updated.${NC}"
    fi

    # Continue with any other operations that require DOMAIN_NAME
fi


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
echo -e "${GREEN}Modifying dhclient.conf file (automaticaly overwriteing resolve.conf) ${NC}"

sleep 0.5 # delay for 0.5 seconds
echo

# Path to the dhclient.conf file
DHCLIENT_CONF="/etc/dhcp/dhclient.conf"

# Check if the dhclient.conf file exists
if [ ! -f "$DHCLIENT_CONF" ]; then
    echo -e "${RED}Error: $DHCLIENT_CONF does not exist. ${NC}"
    exit 1
fi

# Backup the original file before making changes
sudo cp $DHCLIENT_CONF "${DHCLIENT_CONF}.bak"
if [ $? -ne 0 ]; then
    echo -e "${RED}Error: Failed to backup the original dhclient.conf file. ${NC}"
    exit 1
fi

# Replace the specified lines
sudo sed -i 's/domain-name, domain-name-servers, domain-search, host-name,/domain-name, domain-search, host-name,/' $DHCLIENT_CONF
if [ $? -ne 0 ]; then
    echo -e "${RED}Error: Failed to replace the first specified line. ${NC}"
    exit 1
fi

sudo sed -i 's/dhcp6.name-servers, dhcp6.domain-search, dhcp6.fqdn, dhcp6.sntp-servers,/dhcp6.domain-search, dhcp6.fqdn, dhcp6.sntp-servers,/' $DHCLIENT_CONF
if [ $? -ne 0 ]; then
    echo -e "${RED}Error: Failed to replace the second specified line. ${NC}"
    exit 1
fi

# Get the primary IP address of the machine
IP_ADDRESS=$(hostname -I | awk '{print $1}')
if [ -z "$IP_ADDRESS" ]; then
    echo -e "${RED}Error: Failed to obtain the IP address of the machine. ${NC}"
    exit 1
fi

# Check and replace the "prepend domain-name-servers" line with the machine's IP address
sudo sed -i "/^#prepend domain-name-servers 127.0.0.1;/a prepend domain-name-servers ${IP_ADDRESS};" $DHCLIENT_CONF
if [ $? -ne 0 ]; then
    echo -e "${RED}Error: Failed to insert the machine's IP address. ${NC}"
    exit 1
fi

# Now, find the line with the machine's IP address and add the 127.0.0.1 below it
sudo sed -i "/^prepend domain-name-servers ${IP_ADDRESS};/a prepend domain-name-servers 127.0.0.1;" $DHCLIENT_CONF
if [ $? -ne 0 ]; then
    echo -e "${RED}Error: Failed to insert the 127.0.0.1 address below the machine's IP address. ${NC}"
    exit 1
fi

echo -e "${GREEN}Modifications completed successfully. ${NC}"


########################################
# Prepare Unbound configuration file #
########################################
echo
echo -e "${GREEN}Preparing Unbound configuration file (unbound.conf) ${NC}"

sleep 0.5 # delay for 0.5 seconds
echo

# Extract the domain name from /etc/resolv.conf
DOMAIN_NAME_LOCAL=$(grep '^domain' /etc/resolv.conf | awk '{print $2}')

# Check if the domain name was found
if [ -z "$DOMAIN_NAME_LOCAL" ]; then
  echo -e "${RED}Domain name not found in ${NC} /etc/resolv.conf"
  exit 1
fi

# Replace DOMAIN_NAME placeholder in unbound.conf with the extracted domain name
sed -i "s/DOMAIN_NAME/$DOMAIN_NAME_LOCAL/g" unbound.conf

echo -e "${GREEN}Domain name $DOMAIN_NAME_LOCAL has been set in ${NC} unbound.conf"


##############################
# Replace configuration file #
##############################
echo
echo -e "${GREEN}Adding new configuration file to Unbound (unbound.conf) ${NC}"

sleep 0.5 # delay for 0.5 seconds
echo

sudo cp unbound.conf /etc/unbound/unbound.conf


##########################
# Prompt user for reboot #
##########################

while true; do
    read -p "Do you want to reboot the server now (recommended)? (yes/no): " response
    case "${response,,}" in
        yes|y) echo -e "${GREEN}Rebooting the server...${NC}"; sudo reboot; break ;;
        no|n) echo -e "${RED}Reboot cancelled.${NC}"; exit 0 ;;
        *) echo -e "${YELLOW}Invalid response. Please answer${NC} yes or no." ;;
    esac
done
