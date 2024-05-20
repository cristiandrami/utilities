#!/bin/bash

# Installazione di Homebrew se non è già installato
if ! command -v brew &> /dev/null
then
    echo "Installing Homebrew..."
    /bin/bash -c "$(curl -fsSL https://raw.githubusercontent.com/Homebrew/install/HEAD/install.sh)"
fi

# Installazione di nmap
echo "Installing nmap..."
brew install nmap

# Installazione di nikto
echo "Installing nikto..."
brew install nikto

# Installazione di dirb
echo "Installing dirb..."
brew install dirb

echo "All commands installed successfully."

