#!/bin/bash

# omg-cli installation script
# This script installs yggdrasil tunnel with SSH access

set -euo pipefail

# Colors for output
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
NC='\033[0m' # No Color

# Print colored output
print_info() {
    echo -e "${BLUE}[INFO]${NC} $1"
}

print_success() {
    echo -e "${GREEN}[SUCCESS]${NC} $1"
}

print_warning() {
    echo -e "${YELLOW}[WARNING]${NC} $1"
}

print_error() {
    echo -e "${RED}[ERROR]${NC} $1"
}

# Check if running as root
check_root() {
    if [[ $EUID -eq 0 ]]; then
        print_error "This script should not be run as root. Run as a regular user."
        exit 1
    fi
}

# Detect OS and package manager
detect_os() {
    if [ -f /etc/os-release ]; then
        . /etc/os-release
        OS=$NAME
        DISTRO=$ID
        VER=$VERSION_ID
    else
        print_error "Cannot detect OS. Unsupported system."
        exit 1
    fi
    
    print_info "Detected OS: $OS ($DISTRO $VER)"
    
    # Determine package manager
    if command -v apt-get >/dev/null 2>&1; then
        PKG_MANAGER="apt-get"
        INSTALL_CMD="sudo apt-get install -y"
    elif command -v yum >/dev/null 2>&1; then
        PKG_MANAGER="yum"
        INSTALL_CMD="sudo yum install -y"
    elif command -v dnf >/dev/null 2>&1; then
        PKG_MANAGER="dnf"
        INSTALL_CMD="sudo dnf install -y"
    elif command -v pacman >/dev/null 2>&1; then
        PKG_MANAGER="pacman"
        INSTALL_CMD="sudo pacman -S --noconfirm"
    elif command -v zypper >/dev/null 2>&1; then
        PKG_MANAGER="zypper"
        INSTALL_CMD="sudo zypper install -y"
    else
        print_error "Unsupported package manager. Cannot install dependencies."
        exit 1
    fi
    
    print_info "Package manager detected: $PKG_MANAGER"
}

# Install dependencies
install_dependencies() {
    print_info "Installing dependencies..."
    
    # Install required packages
    $INSTALL_CMD curl wget gnupg iptables
    
    # Check if yggdrasil is available in repos
    if ! command -v yggdrasil >/dev/null 2>&1; then
        print_info "Yggdrasil not found in repositories, installing from GitHub..."
        
        # Download latest yggdrasil release
        LATEST_VERSION=$(curl -s https://api.github.com/repos/yggdrasil-network/yggdrasil-go/releases/latest | grep tag_name | cut -d '"' -f 4)
        ARCH=$(uname -m)
        
        case $ARCH in
            x86_64)
                YGG_FILE="yggdrasil-${LATEST_VERSION}-linux-amd64.tar.gz"
                ;;
            aarch64|armv8*)
                YGG_FILE="yggdrasil-${LATEST_VERSION}-linux-arm64.tar.gz"
                ;;
            armv7l)
                YGG_FILE="yggdrasil-${LATEST_VERSION}-linux-arm.tar.gz"
                ;;
            *)
                print_error "Unsupported architecture: $ARCH"
                exit 1
                ;;
        esac
        
        cd /tmp
        wget "https://github.com/yggdrasil-network/yggdrasil-go/releases/download/${LATEST_VERSION}/${YGG_FILE}"
        tar -xzf "$YGG_FILE"
        
        # Install yggdrasil binaries
        sudo cp yggdrasil-${LATEST_VERSION}/yggdrasil /usr/local/bin/
        sudo cp yggdrasil-${LATEST_VERSION}/yggdrasilctl /usr/local/bin/
        sudo chmod +x /usr/local/bin/yggdrasil /usr/local/bin/yggdrasilctl
        
        # Clean up
        rm -rf "yggdrasil-${LATEST_VERSION}" "$YGG_FILE"
    fi
    
    # Install openssh-server if not present
    if ! command -v sshd >/dev/null 2>&1; then
        $INSTALL_CMD openssh-server
    fi
    
    print_success "Dependencies installed successfully"
}

# Configure firewall rules
configure_firewall() {
    print_info "Configuring firewall rules..."
    
    # Detect firewall type
    if command -v iptables >/dev/null 2>&1; then
        FIREWALL_TYPE="iptables"
    elif command -v nft >/dev/null 2>&1; then
        FIREWALL_TYPE="nftables"
    elif command -v ufw >/dev/null 2>&1; then
        FIREWALL_TYPE="ufw"
    else
        print_warning "No known firewall detected. Skipping firewall configuration."
        return 0
    fi
    
    print_info "Firewall type detected: $FIREWALL_TYPE"
    
    case $FIREWALL_TYPE in
        "iptables")
            # Allow SSH on the configured port
            sudo iptables -A INPUT -p tcp --dport $SSH_PORT -j ACCEPT
            # Allow yggdrasil traffic
            sudo iptables -A INPUT -p tcp --dport 9001 -j ACCEPT
            sudo iptables -A OUTPUT -p tcp --sport 9001 -j ACCEPT
            # Block all other incoming connections
            sudo iptables -A INPUT -j DROP
            ;;
        "nftables")
            # Create basic ruleset for nftables
            sudo nft add table inet filter
            sudo nft add chain inet filter input '{ type filter hook input priority 0 ; policy drop ; }'
            sudo nft add rule inet filter input iif "lo" accept
            sudo nft add rule inet filter input ip protocol icmp accept
            sudo nft add rule inet filter input tcp dport $SSH_PORT accept
            sudo nft add rule inet filter input tcp dport 9001 accept
            ;;
        "ufw")
            # Reset UFW rules
            echo "y" | sudo ufw reset
            # Set default policies
            sudo ufw default deny incoming
            sudo ufw default allow outgoing
            # Allow SSH on configured port
            sudo ufw allow $SSH_PORT/tcp
            # Enable UFW
            echo "y" | sudo ufw enable
            ;;
    esac
    
    print_success "Firewall configured to allow only SSH on port $SSH_PORT"
}

# Start yggdrasil service
setup_yggdrasil() {
    print_info "Setting up Yggdrasil network..."
    
    # Generate basic yggdrasil config
    if [ ! -f /etc/yggdrasil.conf ]; then
        sudo yggdrasil -genconf > /tmp/yggdrasil.conf
        sudo mv /tmp/yggdrasil.conf /etc/yggdrasil.conf
    fi
    
    # Create systemd service file
    cat << EOF | sudo tee /etc/systemd/system/yggdrasil.service
[Unit]
Description=Yggdrasil Node
After=network.target

[Service]
Type=simple
ExecStart=/usr/local/bin/yggdrasil -useconffile /etc/yggdrasil.conf
Restart=always
RestartSec=10

[Install]
WantedBy=multi-user.target
EOF
    
    # Enable and start yggdrasil service
    sudo systemctl daemon-reload
    sudo systemctl enable yggdrasil
    sudo systemctl start yggdrasil
    
    # Wait a bit for yggdrasil to start
    sleep 5
    
    print_success "Yggdrasil service started"
}

# Configure SSH for Yggdrasil interface
configure_ssh() {
    print_info "Configuring SSH server..."
    
    # Backup original config
    sudo cp /etc/ssh/sshd_config /etc/ssh/sshd_config.backup
    
    # Modify SSH config to listen on yggdrasil interface
    # First get yggdrasil IP
    YGG_IP=$(yggdrasilctl getSelf | grep -oE '([0-9a-fA-F]{1,4}:){7}[0-9a-fA-F]{1,4}|([0-9]{1,3}\.){3}[0-9]{1,3}' | head -1)
    
    if [ -z "$YGG_IP" ]; then
        print_error "Could not get Yggdrasil IP address"
        exit 1
    fi
    
    # Update SSH config to bind to yggdrasil interface
    sudo sed -i.bak '/^#*ListenAddress/d' /etc/ssh/sshd_config
    echo "ListenAddress $YGG_IP" | sudo tee -a /etc/ssh/sshd_config
    
    # Set SSH port
    sudo sed -i.bak "s/^#*Port .*/Port $SSH_PORT/" /etc/ssh/sshd_config
    
    # Restart SSH service
    sudo systemctl restart sshd
    
    print_success "SSH configured to listen on Yggdrasil IP $YGG_IP:$SSH_PORT"
}

# Create or use existing user
manage_user() {
    print_info "Managing SSH user..."
    
    while true; do
        read -p "Do you want to create a new user? (y/n): " yn
        case $yn in
            [Yy]* ) 
                CREATE_NEW_USER=true
                break
                ;;
            [Nn]* ) 
                CREATE_NEW_USER=false
                break
                ;;
            * ) echo "Please answer yes or no.";;
        esac
    done
    
    if [ "$CREATE_NEW_USER" = true ]; then
        # Generate random username
        USERNAME="omguser$(openssl rand -hex 4)"
        PASSWORD=$(openssl rand -base64 12)
        
        # Create user
        sudo useradd -m -s /bin/bash "$USERNAME"
        echo "$USERNAME:$PASSWORD" | sudo chpasswd
        
        print_success "Created user: $USERNAME with password: $PASSWORD"
    else
        # Use existing user
        read -p "Enter existing username: " USERNAME
        
        if ! id "$USERNAME" &>/dev/null; then
            print_error "User $USERNAME does not exist"
            exit 1
        fi
        
        # Generate temporary password
        PASSWORD=$(openssl rand -base64 12)
        echo "$USERNAME:$PASSWORD" | sudo chpasswd
        
        print_success "Using existing user: $USERNAME with new password: $PASSWORD"
    fi
    
    # Get yggdrasil IP again to make sure it's available
    YGG_IP=$(yggdrasilctl getSelf | grep -oE '([0-9a-fA-F]{1,4}:){7}[0-9a-fA-F]{1,4}|([0-9]{1,3}\.){3}[0-9]{1,3}' | head -1)
    
    # Display connection information
    echo ""
    echo "==========================================="
    echo "CONNECTION INFORMATION:"
    echo "Yggdrasil Address: $YGG_IP"
    echo "Port: $SSH_PORT"
    echo "Username: $USERNAME"
    echo "Password: $PASSWORD"
    echo "Full connection command: ssh $USERNAME@$YGG_IP -p $SSH_PORT"
    echo "==========================================="
    echo ""
}

# Main execution
main() {
    print_info "Starting omg-cli installation..."
    
    check_root
    detect_os
    
    # Ask user for SSH port
    read -p "Enter SSH port to use (default: 22): " SSH_PORT_INPUT
    SSH_PORT=${SSH_PORT_INPUT:-22}
    
    print_info "Using SSH port: $SSH_PORT"
    
    install_dependencies
    setup_yggdrasil
    configure_firewall
    configure_ssh
    manage_user
    
    print_success "Installation completed successfully!"
    print_info "The secure tunnel is now active through Yggdrasil network."
}

# Run main function
main "$@"