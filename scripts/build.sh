#!/bin/bash

# Copyright (c) Microsoft Corporation.
# Licensed under the MIT License.

# Exit immediately if a command exits with a non-zero status
set -e

# Default Ubuntu distribution version
UBUNTU_DISTRIBUTION="22.04"

show_help() {
    echo "Usage: $(basename "$0") [UBUNTU_DISTRIBUTION] [OPTIONS]"
    echo ""
    echo "Arguments:"
    echo "  UBUNTU_DISTRIBUTION  Ubuntu distribution version (Default: 22.04)"
    echo ""
    echo "Options:"
    echo "  --help               Display this help message and exit"
    echo ""
    echo "Description:"
    echo "  This script automates the installation of dependencies, configuration, and building"
    echo "  of a project using CMake. It also handles pre- and post-installation scripts and"
    echo "  runs example tests."
    echo ""
    echo "Usage:"
    echo "  1. Run the script without any arguments to use default distribution (22.04):"
    echo "       ./$(basename "$0")"
    echo ""
    echo "  2. Run the script with a specific Ubuntu distribution:"
    echo "       ./$(basename "$0") 22.04"
    echo ""
    echo "  3. Run the script with '--help' to see available options and usage examples:"
    echo "       ./$(basename "$0") --help"
    echo ""
    echo "  4. Customize the build process by modifying CMake options directly:"
    echo "       cmake -S . -B build -DKMPP_DEBUG=OFF"
    echo ""
    echo "Compilation Options:"
    echo "  These CMake options control specific features during the build process:"
    echo ""
    echo "  KMPP_NGINX                  Build nginx example. (Default: ON)"
    echo "  KMPP_DEBUG                  Build with Debug options. (Default: OFF)"
    echo "  KMPP_RUNNING_ON_CONTAINERS  Running on containers. (Default: OFF)"
    echo "  KMPP_OPENSSL_SUPPORT        Build with a dependency on OpenSSL. (Default: ON)"
    echo "  KMPP_SYMMETRIC_KEY_SUPPORT  Build with support for symmetric key. (Default: ON)"
    echo "  KMPP_INSTALL_SERVICE        Install Systemd service. (Default: ON)"
    echo ""
    echo "Example Compilation Command:"
    echo "  To build with the debug option enabled:"
    echo "    cmake -S . -B build -DKMPP_DEBUG=ON"
    exit 0
}

# Parse command line arguments
if [[ "$1" == "--help" ]]; then
    show_help
elif [[ -n "$1" && "$1" != "--help" ]]; then
    UBUNTU_DISTRIBUTION="$1"
fi

echo "Using Ubuntu distribution: $UBUNTU_DISTRIBUTION"

# Update package lists
sudo apt-get update  
sudo apt-get install -y pkg-config cmake curl libcurl4-openssl-dev libglib2.0-dev libgtest-dev libdbus-1-dev uuid-dev libssl-dev build-essential googletest libtss2-dev libjansson-dev  
curl -sSL -O https://packages.microsoft.com/config/ubuntu/${UBUNTU_DISTRIBUTION}/packages-microsoft-prod.deb
if [ -f packages-microsoft-prod.deb ]; then
    sudo dpkg -i packages-microsoft-prod.deb
    sudo rm packages-microsoft-prod.deb
else
    echo "Failed to download packages-microsoft-prod.deb"
    exit 1
fi
sudo apt-get update
sudo apt search symcrypt
echo "deb https://packages.microsoft.com/ubuntu/${UBUNTU_DISTRIBUTION}/prod testing main" | sudo tee /etc/apt/sources.list.d/microsoft-test.list
sudo apt-get update
sudo apt install -y symcrypt

# run the create_certs.sh script
./scripts/create_certs.sh 

# Configure CMake
cmake -S . -B build

# Build the project
cmake --build build

# Navigate back to the scripts directory
cd scripts

# Run pre-installation script
chmod +x postinst preinst
sh ./preinst

# Navigate back to the build directory
cd ../build

# Install the project
sudo make install

# Navigate back to the scripts directory
cd ../scripts

# Run post-installation script
sudo sh ./postinst

rm -rf certs

# Navigate to the examples directory and run the tests
cd ../example
chmod +x generate_pfx.sh
./generate_pfx.sh

./../build/bin/kmppexample
