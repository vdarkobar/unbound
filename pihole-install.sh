#!/usr/bin/expect -f

set timeout 120

# Spawn the installation command directly
spawn /bin/bash -c "curl -sSL https://install.pi-hole.net | sudo bash"

# Example handling of the installation script prompts
expect "Existing Install Detected" {
    send "yes\r"
}

# Continue with other prompts as necessary

expect eof
