#!/bin/bash

set -e

echo "Updating package lists..."
sudo apt-get update

# Installazione di nmap
echo "Installing nmap..."
sudo apt install nmap -y

# Installazione di nikto
echo "Installing nikto..."
sudo apt install nikto -y

# Installazione di dirb
echo "Installing dirb..."
sudo apt install dirb -y

# Installazione di ffuf (via Go)
echo "Installing ffuf..."
sudo apt install ffuf

# Installazione di snap 
sudo apt install snapd -y
sudo systemctl enable snapd
sudo systemctl start snapd

# Installazione di seclists
echo "Installing seclists..."
sudo snap install seclists

echo "All tools installed successfully!"
