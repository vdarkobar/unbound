#!/bin/bash

clear

GREEN='\033[0;32m'
RED='\033[0;31m'
YELLOW='\033[0;33m'
NC='\033[0m'

# Install Unbound

if ! sudo apt -y install unbound net-tools tcpdump ca-certificates; then
    echo "Failed to install packages. Exiting."
    exit 1
fi

########################################################################

# Create backup files

# Backup the existing /etc/hosts file
if [ ! -f /etc/hosts.backup ]; then
    sudo cp /etc/hosts /etc/hosts.backup
    echo -e "${GREEN}Backup of /etc/hosts created.${NC}"
else
    echo -e "${GREEN}Backup of /etc/hosts already exists. Skipping backup.${NC}"
fi

# Backup original /etc/cloud/cloud.cfg file before modifications
CLOUD_CFG="/etc/cloud/cloud.cfg"
if [ ! -f "$CLOUD_CFG.bak" ]; then
    sudo cp "$CLOUD_CFG" "$CLOUD_CFG.bak"
    echo -e "${GREEN}Backup of $CLOUD_CFG created.${NC}"
else
    echo -e "${GREEN}Backup of $CLOUD_CFG already exists. Skipping backup.${NC}"
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
        echo -e "${GREEN}Backup of $file already exists. Skipping backup.${NC}"
    fi
done

########################################################################

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
        echo -e "${RED}Could not determine the host IP address or hostname. Skipping /etc/hosts update!!!${NC}"
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

########################################################################
