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
echo -e "${GREEN} This script will install and configure Unbound DNS and, optionaly, Pi-Hole Add blocker ${NC}"

sleep 0.5 # delay for 0.5 seconds
echo

echo -e "${GREEN} You'll be asked to enter: ${NC}"
echo -e " - One Local Subnet for Access Control"
echo -e " - One entry for Local DNS Lookup (hostname/ip)"
echo -e " - Public Key to configure your SSH access to container"
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


####################
# Install packages #
####################

echo -e "${GREEN} Installing Unbound and other packages ${NC}"

sleep 0.5 # delay for 0.5 seconds
echo

# Update the package repositories
if ! sudo apt update; then
    echo -e "${RED}Failed to update package repositories. Exiting.${NC}"
    exit 1
fi

if ! sudo apt -y install unbound ufw fail2ban ca-certificates curl unattended-upgrades; then
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

# Backup the existing /etc/dhcp/dhclient.conf file
if [ ! -f /etc/dhcp/dhclient.conf.backup ]; then
    sudo cp /etc/dhcp/dhclient.conf /etc/dhcp/dhclient.conf.backup
    echo -e "${GREEN} Backup of${NC} /etc/dhcp/dhclient.conf ${GREEN}created.${NC}"
else
    echo -e "${YELLOW} Backup of${NC} /etc/dhcp/dhclient.conf ${YELLOW}already exists. Skipping backup.${NC}"
fi

# Backup the existing 50unattended-upgrades file
if [ ! -f /etc/apt/apt.conf.d/50unattended-upgrades.backup ]; then
    sudo cp /etc/apt/apt.conf.d/50unattended-upgrades /etc/apt/apt.conf.d/50unattended-upgrades.backup
    echo -e "${GREEN} Backup of${NC} /etc/apt/apt.conf.d/50unattended-upgrades ${GREEN}created.${NC}"
else
    echo -e "${YELLOW} Backup of${NC} /etc/apt/apt.conf.d/50unattended-upgrades ${YELLOW}already exists. Skipping backup.${NC}"
fi

# Backup the existing /etc/fail2ban/jail.local file
if [ ! -f /etc/fail2ban/jail.local.backup ]; then
    sudo cp /etc/fail2ban/jail.local /etc/fail2ban/jail.local.backup
    echo -e "${GREEN} Backup of${NC} /etc/fail2ban/jail.local ${GREEN}created.${NC}"
else
    echo -e "${YELLOW} Backup of${NC} /etc/fail2ban/jail.local ${YELLOW}already exists. Skipping backup.${NC}"
fi

# Backup the existing /etc/ssh/sshd_config file
if [ ! -f /etc/ssh/sshd_config.backup ]; then
    sudo cp /etc/ssh/sshd_config /etc/ssh/sshd_config.backup
    echo -e "${GREEN} Backup of${NC} /etc/ssh/sshd_config ${GREEN}created.${NC}"
else
    echo -e "${YELLOW} Backup of${NC} /etc/ssh/sshd_config ${YELLOW}already exists. Skipping backup.${NC}"
fi

# Backup the existing /etc/pam.d/sshd file
if [ ! -f /etc/pam.d/sshd.backup ]; then
    sudo cp /etc/pam.d/sshd /etc/pam.d/sshd.backup
    echo -e "${GREEN} Backup of${NC} /etc/pam.d/sshd ${GREEN}created.${NC}"
else
    echo -e "${YELLOW} Backup of${NC} /etc/pam.d/sshd ${YELLOW}already exists. Skipping backup.${NC}"
fi

# Backup the existing /etc/fstab file
if [ ! -f /etc/fstab.backup ]; then
    sudo cp /etc/fstab /etc/fstab.backup
    echo -e "${GREEN} Backup of${NC} /etc/fstab ${GREEN}created.${NC}"
else
    echo -e "${YELLOW} Backup of${NC} /etc/fstab ${YELLOW}already exists. Skipping backup.${NC}"
fi

# Backup the existing /etc/sysctl.conf file
if [ ! -f /etc/sysctl.conf.backup ]; then
    sudo cp /etc/sysctl.conf /etc/sysctl.conf.backup
    echo -e "${GREEN} Backup of${NC} /etc/sysctl.conf ${GREEN}created.${NC}"
else
    echo -e "${YELLOW} Backup of${NC} /etc/sysctl.conf ${YELLOW}already exists. Skipping backup.${NC}"
fi

# Before modifying Unbound configuration files, create backups if they don't already exist (option for multiple files)
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


############################################
# Automatically enable unattended-upgrades #
############################################

echo -e "${GREEN} Enabling unattended-upgrades ${NC}"

# Enable unattended-upgrades
if echo unattended-upgrades unattended-upgrades/enable_auto_updates boolean true | sudo debconf-set-selections && sudo dpkg-reconfigure -f noninteractive unattended-upgrades; then
    echo
    echo -e "${GREEN} Unattended-upgrades enabled successfully.${NC}"
    echo
else
    echo -e "${RED} Failed to enable unattended-upgrades. Exiting.${NC}"
    exit 1
fi

# Define the file path
FILEPATH="/etc/apt/apt.conf.d/50unattended-upgrades"

# Check if the file exists before attempting to modify it
if [ ! -f "$FILEPATH" ]; then
    echo -e "${RED}$FILEPATH does not exist. Exiting.${NC}"
    exit 1
fi

# Uncomment the necessary lines
if sudo sed -i 's|//Unattended-Upgrade::Remove-Unused-Kernel-Packages "true";|Unattended-Upgrade::Remove-Unused-Kernel-Packages "true";|g' $FILEPATH \
   && sudo sed -i 's|//Unattended-Upgrade::Remove-New-Unused-Dependencies "true";|Unattended-Upgrade::Remove-New-Unused-Dependencies "true";|g' $FILEPATH \
   && sudo sed -i 's|//Unattended-Upgrade::Remove-Unused-Dependencies "false";|Unattended-Upgrade::Remove-Unused-Dependencies "true";|g' $FILEPATH \
   && sudo sed -i 's|//Unattended-Upgrade::Automatic-Reboot "false";|Unattended-Upgrade::Automatic-Reboot "true";|g' $FILEPATH \
   && sudo sed -i 's|//Unattended-Upgrade::Automatic-Reboot-Time "02:00";|Unattended-Upgrade::Automatic-Reboot-Time "02:00";|g' $FILEPATH; then
    echo -e "${GREEN} Configuration updated successfully.${NC}"
    echo
else
    echo -e "${RED} Failed to update configuration. Please check your permissions and file paths. Exiting.${NC}"
    exit 1
fi

#######################
# Setting up Fail2Ban #
#######################

echo -e "${GREEN}Setting up Fail2Ban...${NC}"

# Check if Fail2Ban is installed
if ! command -v fail2ban-server >/dev/null 2>&1; then
    echo -e "${RED}Fail2Ban is not installed. Please install Fail2Ban and try again. Exiting.${NC}"
    exit 1
fi

# To preserve your custom settings...
if ! sudo cp /etc/fail2ban/jail.conf /etc/fail2ban/jail.local; then
    echo -e "${RED}Failed to copy jail.conf to jail.local. Exiting.${NC}"
    exit 1
fi

# Fixing Debian bug by setting backend to systemd
if ! sudo sed -i 's|backend = auto|backend = systemd|g' /etc/fail2ban/jail.local; then
    echo -e "${RED}Failed to set backend to systemd in jail.local. Exiting.${NC}"
    exit 1
fi

echo -e "${GREEN}Configuring Fail2Ban for SSH protection...${NC}"

# Set the path to the sshd configuration file
config_file="/etc/fail2ban/jail.local"

# Use awk to add "enabled = true" below the second [sshd] line (first is a comment)
if ! sudo awk '/\[sshd\]/ && ++n == 2 {print; print "enabled = true"; next}1' "$config_file" > temp_file || ! sudo mv temp_file "$config_file"; then
    echo -e "${RED}Failed to enable SSH protection. Exiting.${NC}"
    exit 1
fi

# Change bantime to 15m
if ! sudo sed -i 's|bantime  = 10m|bantime  = 15m|g' /etc/fail2ban/jail.local; then
    echo -e "${RED}Failed to set bantime to 15m. Exiting.${NC}"
    exit 1
fi

# Change maxretry to 3
if ! sudo sed -i 's|maxretry = 5|maxretry = 3|g' /etc/fail2ban/jail.local; then
    echo -e "${RED}Failed to set maxretry to 3. Exiting.${NC}"
    exit 1
fi

echo -e "${GREEN}Fail2Ban setup completed.${NC}"
sleep 0.5 # delay for 0.5 seconds
echo


##################
# Setting up UFW #
##################

echo -e "${GREEN} Setting up UFW...${NC}"
echo

# Limit SSH to Port 22/tcp
if ! sudo ufw limit 22/tcp comment "SSH"; then
    echo -e "${RED} Failed to limit SSH access. Exiting.${NC}"
    exit 1
fi

# DNS port 53/udp
if ! sudo ufw allow 53/udp comment "DNS port 53/udp"; then
    echo -e "${RED} Failed to allow DNS port 53/udp. Exiting.${NC}"
    exit 1
fi

# DNS port 53/tcp
if ! sudo ufw allow 53/tcp comment "DNS port 53/tcp"; then
    echo -e "${RED} Failed to allow DNS port 53/tcp. Exiting.${NC}"
    exit 1
fi

# DNS over TLS port 853/tcp
if ! sudo ufw allow 853/tcp comment "DNS over TLS port 853/tcp"; then
    echo -e "${RED} Failed to allow DNS over TLS port 853/tcp. Exiting.${NC}"
    exit 1
fi

# Enable UFW without prompt
if ! sudo ufw --force enable; then
    echo -e "${RED} Failed to enable UFW. Exiting.${NC}"
    exit 1
fi

# Set global rules
if ! sudo ufw default deny incoming || ! sudo ufw default allow outgoing; then
    echo -e "${RED} Failed to set global rules. Exiting.${NC}"
    exit 1
fi

# Reload UFW to apply changes
if ! sudo ufw reload; then
    echo -e "${RED} Failed to reload UFW. Exiting.${NC}"
    exit 1
fi

echo
echo -e "${GREEN} UFW setup completed.${NC}"
sleep 0.5 # delay for 0.5 seconds
echo


##########################
# Securing Shared Memory #
##########################

echo -e "${GREEN}Securing Shared Memory...${NC}"

# Define the line to append
LINE="none /run/shm tmpfs defaults,ro 0 0"

# Append the line to the end of the file
if ! echo "$LINE" | sudo tee -a /etc/fstab > /dev/null; then
    echo -e "${RED}Failed to secure shared memory. Exiting.${NC}"
    exit 1
fi


###############################
# Setting up system variables #
###############################

echo -e "${GREEN}Setting up system variables...${NC}"
echo

# Define the file path
FILEPATH="/etc/sysctl.conf"

# Modify system variables for security enhancements
if ! sudo sed -i 's|#net.ipv4.conf.default.rp_filter=1|net.ipv4.conf.default.rp_filter=1|g' $FILEPATH \
   || ! sudo sed -i 's|#net.ipv4.conf.all.rp_filter=1|net.ipv4.conf.all.rp_filter=1|g' $FILEPATH \
   || ! sudo sed -i 's|#net.ipv4.conf.all.accept_redirects = 0|net.ipv4.conf.all.accept_redirects = 0|g' $FILEPATH \
   || ! sudo sed -i 's|#net.ipv6.conf.all.accept_redirects = 0|net.ipv6.conf.all.accept_redirects = 0|g' $FILEPATH \
   || ! sudo sed -i 's|#net.ipv4.conf.all.send_redirects = 0|net.ipv4.conf.all.send_redirects = 0|g' $FILEPATH \
   || ! sudo sed -i 's|#net.ipv4.conf.all.accept_source_route = 0|net.ipv4.conf.all.accept_source_route = 0|g' $FILEPATH \
   || ! sudo sed -i 's|#net.ipv6.conf.all.accept_source_route = 0|net.ipv6.conf.all.accept_source_route = 0|g' $FILEPATH \
   || ! sudo sed -i 's|#net.ipv4.conf.all.log_martians = 1|net.ipv4.conf.all.log_martians = 1|g' $FILEPATH; then
    echo -e "${RED}Error occurred during system variable configuration. Exiting.${NC}"
    exit 1
fi

# Reload sysctl with the new configuration
if ! sudo sysctl -p; then
    echo -e "${RED}Failed to reload sysctl configuration. Exiting.${NC}"
    exit 1
fi


####################################
# Obtain Public key for SSH access #
####################################

# Get the username running the script
user=$(whoami)

# Path to the authorized_keys
auth_keys="/home/$user/.ssh/authorized_keys"

# Ensure .ssh directory exists
if [ ! -d "/home/$user/.ssh" ]; then
    echo -e "${YELLOW}Creating .ssh directory...${NC}"
    sudo mkdir -p "/home/$user/.ssh" || { echo -e "${RED}Error: Failed to create .ssh directory${NC}"; exit 1; }
    sudo chmod 700 "/home/$user/.ssh" || { echo -e "${RED}Error: Failed to set permissions on .ssh directory${NC}"; exit 1; }
fi

# Ensure authorized_keys file exists
if [ ! -f "$auth_keys" ]; then
    echo -e "${YELLOW}Creating authorized_keys file...${NC}"
    sudo touch "$auth_keys" || { echo -e "${RED}Error: Failed to create authorized_keys file${NC}"; exit 1; }
    sudo chmod 600 "$auth_keys" || { echo -e "${RED}Error: Failed to set permissions on authorized_keys file${NC}"; exit 1; }
fi

# Ask the user for the public key
while true; do
    echo -e "${YELLOW}Please enter your public SSH key (or press Ctrl-C to cancel):${NC}"
    read public_key

    # Check if the input was empty
    if [ -z "$public_key" ]; then
        echo -e "${RED}No input received, please enter a public key.${NC}"
    else
        # Validate the public key format
        if [[ "$public_key" =~ ^ssh-(rsa|dss|ecdsa|ed25519)[[:space:]][A-Za-z0-9+/]+[=]{0,2} ]]; then
            break
        else
            echo -e "${RED}Invalid SSH key format. Please enter a valid SSH public key.${NC}"
        fi
    fi
done

# Append the public key to the authorized_keys
echo "$public_key" | sudo tee -a "$auth_keys" > /dev/null || { echo -e "${RED}Error: Failed to append the public key to authorized_keys${NC}"; exit 1; }

echo -e "${GREEN}Public key added successfully.${NC}"


#################################
# Locking root account password #
#################################

echo -e "${GREEN}Locking root account password...${NC}"
echo

# Attempt to lock the root account password
if ! sudo passwd -l root; then
    echo -e "${RED}Failed to lock root account password. Exiting.${NC}"
    exit 1
fi

sleep 0.5 # delay for 0.5 seconds
echo


############################
# Setting up SSH variables #
############################

echo -e "${GREEN}Setting up SSH variables...${NC}"

# Define the file path
FILEPATH="/etc/ssh/sshd_config"

# Applying multiple sed operations to configure SSH securely. If any fail, an error message will be shown.
if ! (sudo sed -i 's|KbdInteractiveAuthentication no|#KbdInteractiveAuthentication no|g' $FILEPATH \
    && sudo sed -i 's|#LogLevel INFO|LogLevel VERBOSE|g' $FILEPATH \
    && sudo sed -i 's|#PermitRootLogin prohibit-password|PermitRootLogin no|g' $FILEPATH \
    && sudo sed -i 's|#StrictModes yes|StrictModes yes|g' $FILEPATH \
    && sudo sed -i 's|#MaxAuthTries 6|MaxAuthTries 3|g' $FILEPATH \
    && sudo sed -i 's|#MaxSessions 10|MaxSessions 2|g' $FILEPATH \
    && sudo sed -i 's|#IgnoreRhosts yes|IgnoreRhosts yes|g' $FILEPATH \
    && sudo sed -i 's|#PasswordAuthentication yes|PasswordAuthentication no|g' $FILEPATH \
    && sudo sed -i 's|#PermitEmptyPasswords no|PermitEmptyPasswords no|g' $FILEPATH \
    && sudo sed -i 's|UsePAM yes|UsePAM no|g' $FILEPATH \
    && sudo sed -i 's|#GSSAPIAuthentication no|GSSAPIAuthentication no|g' $FILEPATH \
    && sudo sed -i '/# Ciphers and keying/a Ciphers chacha20-poly1305@openssh.com,aes256-gcm@openssh.com,aes128-gcm@openssh.com,aes256-ctr,aes192-ctr,aes128-ctr' $FILEPATH \
    && sudo sed -i '/chacha20-poly1305/a KexAlgorithms curve25519-sha256@libssh.org,diffie-hellman-group-exchange-sha256' $FILEPATH \
    && sudo sed -i '/curve25519-sha256/a Protocol 2' $FILEPATH); then
    echo -e "${RED}Failed to configure SSH variables. Exiting.${NC}"
    exit 1
fi

sleep 0.5 # delay for 0.5 seconds
echo


########################################################
# Disabling ChallengeResponseAuthentication explicitly #
########################################################

echo -e "${GREEN}Disabling ChallengeResponseAuthentication...${NC}"

# Define the line to append
LINE="ChallengeResponseAuthentication no"
FILEPATH="/etc/ssh/sshd_config"

# Check if the line already exists to avoid duplications
if grep -q "^$LINE" "$FILEPATH"; then
    echo -e "${YELLOW}ChallengeResponseAuthentication is already set to no.${NC}"
else
    # Append the line to the end of the file
    if ! echo "$LINE" | sudo tee -a $FILEPATH > /dev/null; then
        echo -e "${RED}Failed to disable ChallengeResponseAuthentication. Exiting.${NC}"
        exit 1
    fi
fi

sleep 0.5 # delay for 0.5 seconds
echo


#############################################
# Allow SSH only for the current Linux user #
#############################################

echo -e "${GREEN}Allowing SSH only for the current Linux user...${NC}"

# Get the current Linux user
user=$(whoami)
FILEPATH="/etc/ssh/sshd_config"

# Check if "AllowUsers" is already set for the current user to avoid duplications
if grep -q "^AllowUsers.*$user" "$FILEPATH"; then
    echo -e "${YELLOW}SSH access is already restricted to the current user (${user}).${NC}"
else
    # Append the user's username to /etc/ssh/sshd_config
    if ! echo "AllowUsers $user" | sudo tee -a $FILEPATH >/dev/null; then
        echo -e "${RED}Failed to restrict SSH access to the current user. Exiting.${NC}"
        exit 1
    fi
    # Restart SSH to apply changes
    if ! sudo systemctl restart ssh; then
        echo -e "${RED}Failed to restart SSH service. Exiting.${NC}"
        exit 1
    fi
fi

sleep 0.5 # delay for 0.5 seconds
echo


################
# Restart sshd #
################

echo -e "${GREEN}Restarting sshd...${NC}"

# Attempt to restart the sshd service
if ! sudo systemctl restart sshd; then
    echo -e "${RED}Failed to restart sshd. Please check the service status and logs for more details. Exiting.${NC}"
    exit 1
fi

sleep 0.5 # delay for 0.5 second
echo


################################
# Setting up working directory #
################################

# Set the WORK_DIR variable
WORK_DIR=$(mktemp -d)

# Scrol to top
num_lines=$(tput lines)
echo -e "\033[${num_lines}A\033[0J"

echo
echo -e "${GREEN} Working directory:${NC} $WORK_DIR"
echo


############################
# Create unbound.conf file #
############################

# Define the path to the directory and the file
file_path="$WORK_DIR/unbound.conf"

# Check if the WORK_DIR variable is set
if [ -z "$WORK_DIR" ]; then
    echo -e "${RED} Error: WORK_DIR variable is not set${NC}"
    exit 1
fi

# Create or overwrite the unbound.conf file, using sudo for permissions
echo -e "${GREEN} Creating unbound.conf file...:${NC} $file_path"

sudo tee "$file_path" > /dev/null <<EOF || { echo "Error: Failed to create $file_path"; exit 1; }
# Unbound configuration file for Debian.
#
# See the unbound.conf(5) man page.
#
# See /usr/share/doc/unbound/examples/unbound.conf for a commented
# reference config file.
#
# The following line includes additional configuration files from the
# /etc/unbound/unbound.conf.d directory.
include-toplevel: "/etc/unbound/unbound.conf.d/*.conf"

# Authoritative, validating, recursive caching DNS with DNS-Over-TLS support
server:

    # Limit permissions 
    username: "unbound"
    # Working directory
    directory: "/etc/unbound"
    # Chain of Trust
    tls-cert-bundle: /etc/ssl/certs/ca-certificates.crt

# Send minimal amount of information to upstream servers to enhance privacy
    qname-minimisation: yes

# Centralized logging
    use-syslog: yes
    # Increase to get more logging.
    verbosity: 2
    # For every user query that fails a line is printed
    val-log-level: 2
    # Logging of DNS queries
    log-queries: yes


# Root hints
    root-hints: /usr/share/dns/root.hints
    harden-dnssec-stripped: yes


# Listen on all interfaces, answer queries from the local subnet (access-control:).
    interface: 0.0.0.0
    interface: ::0

    do-ip4: yes
    do-ip6: yes
    do-udp: yes
    do-tcp: yes

    # Ports
    port: 53
    tls-port: 853

    # Use TCP connections for all upstream communications
    tcp-upstream: yes


# perform prefetching of almost expired DNS cache entries.
    prefetch: yes


# Enable DNS Cache
    cache-max-ttl: 14400
    cache-min-ttl: 1200


# Unbound Privacy and Security
    aggressive-nsec: yes
    hide-identity: yes
    hide-version: yes
    use-caps-for-id: yes


# Define Private Network and Access Control Lists (ACLs)
    private-address: 192.168.0.0/16
    private-address: 169.254.0.0/16
    private-address: 172.16.0.0/12
    private-address: 10.0.0.0/8
    private-address: fd00::/8
    private-address: fe80::/10

    # Control which clients are allowed to make (recursive) queries
    access-control: 127.0.0.1/32 allow_snoop
    access-control: ::1 allow_snoop
    access-control: 127.0.0.0/8 allow
    access-control: LOCAL_SUBNET_ACCESS allow

    # Setup Local Domain
    private-domain: "DOMAIN_NAME_LOCAL"
    domain-insecure: "DOMAIN_NAME_LOCAL"
    local-zone: "DOMAIN_NAME_LOCAL." static

    # A Records Local
    local-data: "HOST_NAME_LOCAL.DOMAIN_NAME_LOCAL. IN A IP_LOCAL"

    # Reverse Lookups Local
    local-data-ptr: "IP_LOCAL HOST_NAME_LOCAL.DOMAIN_NAME_LOCAL"


   # Blocking Ad Server domains. Google's AdSense, DoubleClick and Yahoo
   # account for a 70 percent share of all advertising traffic. Block them.
   # Not guarantied use browser extensions like uBlock Origin, Adblock Plus,
   # or network-wide ad blockers e.g. Pi-hole
   local-zone: "doubleclick.net" redirect
   local-data: "doubleclick.net A 127.0.0.1"
   local-zone: "googlesyndication.com" redirect
   local-data: "googlesyndication.com A 127.0.0.1"
   local-zone: "googleadservices.com" redirect
   local-data: "googleadservices.com A 127.0.0.1"
   local-zone: "google-analytics.com" redirect
   local-data: "google-analytics.com A 127.0.0.1"
   local-zone: "ads.youtube.com" redirect
   local-data: "ads.youtube.com A 127.0.0.1"
   local-zone: "adserver.yahoo.com" redirect
   local-data: "adserver.yahoo.com A 127.0.0.1"
   local-zone: "ask.com" redirect
   local-data: "ask.com A 127.0.0.1"


# Unbound Performance Tuning and Tweak
    num-threads: 4
    msg-cache-slabs: 8
    rrset-cache-slabs: 8
    infra-cache-slabs: 8
    key-cache-slabs: 8
    rrset-cache-size: 256m
    msg-cache-size: 128m
    so-rcvbuf: 8m


# Use DNS over TLS
forward-zone:
    name: "."
    forward-tls-upstream: yes
    # Quad9 DNS
    forward-addr: 9.9.9.9@853#dns.quad9.net
    forward-addr: 149.112.112.112@853#dns.quad9.net
    forward-addr: 2620:fe::11@853#dns.quad9.net
    forward-addr: 2620:fe::fe:11@853#dns.quad9.net 
    # Quad9 DNS (Malware Blocking + Privacy) slower
 #   forward-addr: 9.9.9.11@853#dns11.quad9.net
 #   forward-addr: 149.112.112.11@853#dns11.quad9.net
 #   forward-addr: 2620:fe::11@853#dns11.quad9.net
 #   forward-addr: 2620:fe::fe:11@853#dns11.quad9.net

    # Cloudflare DNS
    forward-addr: 1.1.1.1@853#cloudflare-dns.com
    forward-addr: 1.0.0.1@853#cloudflare-dns.com
    forward-addr: 2606:4700:4700::1111@853#cloudflare-dns.com
    forward-addr: 2606:4700:4700::1001@853#cloudflare-dns.com
    # Cloudflare DNS (Malware Blocking) slower
 #   forward-addr: 1.1.1.2@853#cloudflare-dns.com
 #   forward-addr: 2606:4700:4700::1112@853#cloudflare-dns.com
 #   forward-addr: 1.0.0.2@853#cloudflare-dns.com
 #   forward-addr: 2606:4700:4700::1002@853#cloudflare-dns.com

    # Google
#    forward-addr: 8.8.8.8@853#dns.google
#    forward-addr: 8.8.4.4@853#dns.google
#    forward-addr: 2001:4860:4860::8888@853#dns.google
#    forward-addr: 2001:4860:4860::8844@853#dns.google
EOF

# Check if the file was created successfully
if [ $? -ne 0 ]; then
    echo
    echo -e "${RED} Error: Failed to create${NC} $file_path"
    exit 1
fi

echo
echo -e "${GREEN} unbound.conf file created successfully:${NC} $file_path"
echo


########################################
# Preparing Unbound configuration file #
########################################

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
sed -i "s/DOMAIN_NAME_LOCAL/$DOMAIN_NAME_LOCAL/g" $file_path

echo -e "${GREEN} Domain name${NC} $DOMAIN_NAME_LOCAL ${GREEN}has been set in${NC} $file_path"
sleep 1 # delay for 1 second

# User input
#num_lines=$(tput lines)
#echo -e "\033[${num_lines}A\033[0J"

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

sed -i "s/DOMAIN_NAME_LOCAL/$DOMAIN_NAME_LOCAL/g" $file_path

sleep 0.5 # delay for 0.5 seconds

# Attempt to replace placeholders in unbound.conf
if sed -i "s:LOCAL_SUBNET_ACCESS:$LOCAL_SUBNET_ACCESS:g" $file_path; then
  echo -e "${GREEN} Local Subnet applied successfully. ${NC}"
else
  echo -e "${RED} Error replacing Subnet Address. ${NC}"
  exit 1
fi

if sed -i "s:HOST_NAME_LOCAL:$HOST_NAME_LOCAL:g" $file_path; then
  echo -e "${GREEN} Host name applied successfully. ${NC}"
else
  echo -e "${RED} Error replacing Host Name. ${NC}"
  exit 1
fi

if sed -i "s:IP_LOCAL:$IP_LOCAL:g" $file_path; then
  echo -e "${GREEN} IP Address applied successfully."
else
  echo -e "${RED} Error replacing IP Address. ${NC}"
  exit 1
fi

echo -e "${GREEN} Configuration file updated successfully. ${NC}"
echo

sleep 0.5 # delay for 0.5 seconds


######################
# Prepare hosts file #
######################

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
    echo "$new_line"
    echo "============================================"
    # Replace the line containing the current hostname with the new line
    awk -v hostname="$host_name" -v new_line="$new_line" '!($0 ~ hostname) || $0 == new_line' /etc/hosts
} > /tmp/hosts.tmp

# Move the temporary file to /etc/hosts
sudo mv /tmp/hosts.tmp /etc/hosts

echo -e "${GREEN} File${NC} /etc/hosts ${GREEN}has been updated ${NC}"
echo


#####################
# Update root hints #
#####################

echo -e "${GREEN} Updating root hints file ${NC}"

sleep 0.5 # delay for 0.5 seconds
echo

wget https://www.internic.net/domain/named.root -qO- | sudo tee /usr/share/dns/root.hints
echo


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
echo


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


                ##########################
                # Perform hw clock check #
                ##########################
                
#                sudo hwclock --hctosys


                ##############################
                # Create setupVars.conf file #
                ##############################
                
                # Define the path to the directory and the file
                file_path="$WORK_DIR/setupVars.conf"

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


                #################################################################################
                # replace SHA-256 hash placeholder with User defined Password in setupVars.conf #
                #################################################################################
                
                # Path to the configuration file
                config_file="$WORK_DIR/setupVars.conf"

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

#                num_lines=$(tput lines)
#                echo -e "\033[${num_lines}A\033[0J"

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
                config_file="$WORK_DIR/setupVars.conf"

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
                sudo cp $WORK_DIR/setupVars.conf /etc/pihole/setupVars.conf
                if [ $? -eq 0 ]; then
                    echo
                    echo -e "${GREEN} File copied successfully.${NC}"
                else
                    echo -e "${RED} Failed to copy file:${NC} setupVars.conf"
                    exit 1
                fi


                ###########################################
                # Adjust the port nummber in unbound.conf #
                ###########################################
                
                echo
                echo -e "${GREEN} Adjusting Unbound port for Pi-Hole.${NC}"

                sleep 0.5 # delay for 0.5 seconds
                echo

                if sudo sed -i 's/port: 53/port: 5335/' $WORK_DIR/unbound.conf; then
                    echo -e "${GREEN} Configuration update successfully applied to${NC} $WORK_DIR/unbound.conf"
                else
                    echo -e "${RED} Error: Failed to update configuration in${NC} $WORK_DIR/unbound.conf"
                fi


                ####################
                # Prepare Firewall #
                ####################
                
                echo
                echo -e "${GREEN} Preparing firewall for${NC} Pi-Hole Admin Console"

                sleep 0.5 # delay for 0.5 seconds
                echo

                
                # DNS port 53/udp
                if ! sudo ufw allow 80/tcp comment "Pi-Hole Admin Console"; then
                    echo -e "${RED} Failed to allow Pi-Hole Admin Console. Exiting.${NC}"
                    exit 1
                fi

                # Reload UFW to apply changes
                if ! sudo ufw reload; then
                    echo -e "${RED} Failed to reload UFW. Exiting.${NC}"
                    exit 1
                fi
                
                echo


                ##############################
                # Run Pi-Hole install Script #
                ##############################
                
                # Script
                curl -sSL https://install.pi-hole.net | sudo bash

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

if sudo cp $WORK_DIR/unbound.conf /etc/unbound/unbound.conf; then
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

#num_lines=$(tput lines)
#echo -e "\033[${num_lines}A\033[0J"

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
