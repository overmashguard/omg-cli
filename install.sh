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

# Language selection
select_language() {
    echo "Select language / Выберите язык:"
    echo "1) English"
    echo "2) Русский"
    
    while true; do
        read -p "Enter choice (1 or 2): " choice
        case $choice in
            1) 
                LANG=en
                break
                ;;
            2) 
                LANG=ru
                break
                ;;
            *)
                echo "Invalid choice. Please enter 1 or 2."
                ;;
        esac
    done
}

# Load language-specific messages
load_messages() {
    if [ "$LANG" = "en" ]; then
        MSG_INFO="[INFO]"
        MSG_SUCCESS="[SUCCESS]"
        MSG_WARNING="[WARNING]"
        MSG_ERROR="[ERROR]"
        MSG_STARTING_INSTALL="Starting omg-cli installation..."
        MSG_ROOT_ERROR="This script should not be run as root. Run as a regular user."
        MSG_DETECTED_OS="Detected OS: "
        MSG_PKG_MANAGER="Package manager detected: "
        MSG_UNSUPPORTED_PKG="Unsupported package manager. Cannot install dependencies."
        MSG_INSTALLING_DEPS="Installing dependencies..."
        MSG_YGG_NOT_FOUND="Yggdrasil not found in repositories, installing from GitHub..."
        MSG_UNSUPPORTED_ARCH="Unsupported architecture: "
        MSG_DEPS_INSTALLED="Dependencies installed successfully"
        MSG_CONFIG_FIREWALL="Configuring firewall rules..."
        MSG_NO_FIREWALL="No known firewall detected. Skipping firewall configuration."
        MSG_FIREWALL_TYPE="Firewall type detected: "
        MSG_FIREWALL_CONFIGURED="Firewall configured to allow only SSH on port "
        MSG_SETUP_YGG="Setting up Yggdrasil network..."
        MSG_YGG_SERVICE_STARTED="Yggdrasil service started"
        MSG_CONFIG_SSH="Configuring SSH server..."
        MSG_CANNOT_GET_YGG_IP="Could not get Yggdrasil IP address"
        MSG_SSH_CONFIGURED="SSH configured to listen on Yggdrasil IP "
        MSG_MANAGE_USER="Managing SSH user..."
        MSG_CREATE_USER_PROMPT="Do you want to create a new user? (y/n): "
        MSG_PLEASE_ANSWER="Please answer yes or no."
        MSG_EXISTING_USERNAME="Enter existing username: "
        MSG_USER_DOES_NOT_EXIST="User does not exist"
        MSG_CREATED_USER="Created user: "
        MSG_USING_EXISTING_USER="Using existing user: "
        MSG_WITH_PASSWORD=" with password: "
        MSG_WITH_NEW_PASSWORD=" with new password: "
        MSG_CONNECTION_INFO="CONNECTION INFORMATION:"
        MSG_YGG_ADDRESS="Yggdrasil Address: "
        MSG_PORT="Port: "
        MSG_USERNAME="Username: "
        MSG_PASSWORD="Password: "
        MSG_FULL_COMMAND="Full connection command: ssh "
        MSG_INSTALL_COMPLETE="Installation completed successfully!"
        MSG_SECURE_TUNNEL_ACTIVE="The secure tunnel is now active through Yggdrasil network."
        MSG_ENTER_SSH_PORT="Enter SSH port to use (default: 22): "
        MSG_USING_SSH_PORT="Using SSH port: "
        MSG_ASK_CREATE_USER="Do you want to create a new user? (y/n): "
        MSG_ENTER_EXISTING_USERNAME="Enter existing username: "
        MSG_USER_NOT_EXISTS="User does not exist"
        MSG_GENERATED_USER="Created user: "
        MSG_NEW_PASSWORD=" with password: "
        MSG_UPDATED_PASSWORD=" with new password: "
        MSG_CONN_INFO_HEADER="==========================================="
        MSG_CONN_INFO_FOOTER="==========================================="
        MSG_CONN_INFO_DETAILS="Yggdrasil Address: "
        MSG_CONN_INFO_PORT="Port: "
        MSG_CONN_INFO_USER="Username: "
        MSG_CONN_INFO_PASS="Password: "
        MSG_CONN_INFO_CMD="Full connection command: ssh "
    else
        MSG_INFO="[ИНФО]"
        MSG_SUCCESS="[УСПЕШНО]"
        MSG_WARNING="[ПРЕДУПРЕЖДЕНИЕ]"
        MSG_ERROR="[ОШИБКА]"
        MSG_STARTING_INSTALL="Начинается установка omg-cli..."
        MSG_ROOT_ERROR="Этот скрипт не следует запускать от имени root. Запустите как обычный пользователь."
        MSG_DETECTED_OS="Обнаруженная ОС: "
        MSG_PKG_MANAGER="Обнаружен менеджер пакетов: "
        MSG_UNSUPPORTED_PKG="Неподдерживаемый менеджер пакетов. Невозможно установить зависимости."
        MSG_INSTALLING_DEPS="Установка зависимостей..."
        MSG_YGG_NOT_FOUND="Yggdrasil не найден в репозиториях, установка из GitHub..."
        MSG_UNSUPPORTED_ARCH="Неподдерживаемая архитектура: "
        MSG_DEPS_INSTALLED="Зависимости успешно установлены"
        MSG_CONFIG_FIREWALL="Настройка правил брандмауэра..."
        MSG_NO_FIREWALL="Не обнаружен известный брандмауэр. Пропуск настройки брандмауэра."
        MSG_FIREWALL_TYPE="Обнаружен тип брандмауэра: "
        MSG_FIREWALL_CONFIGURED="Брандмауэр настроен для разрешения только SSH на порт "
        MSG_SETUP_YGG="Настройка сети Yggdrasil..."
        MSG_YGG_SERVICE_STARTED="Служба Yggdrasil запущена"
        MSG_CONFIG_SSH="Настройка сервера SSH..."
        MSG_CANNOT_GET_YGG_IP="Не удалось получить IP-адрес Yggdrasil"
        MSG_SSH_CONFIGURED="SSH настроен для прослушивания на IP Yggdrasil "
        MSG_MANAGE_USER="Управление пользователем SSH..."
        MSG_CREATE_USER_PROMPT="Вы хотите создать нового пользователя? (д/н): "
        MSG_PLEASE_ANSWER="Пожалуйста, ответьте да или нет."
        MSG_EXISTING_USERNAME="Введите имя существующего пользователя: "
        MSG_USER_DOES_NOT_EXIST="Пользователь не существует"
        MSG_CREATED_USER="Создан пользователь: "
        MSG_USING_EXISTING_USER="Использование существующего пользователя: "
        MSG_WITH_PASSWORD=" с паролем: "
        MSG_WITH_NEW_PASSWORD=" с новым паролем: "
        MSG_CONNECTION_INFO="ИНФОРМАЦИЯ О ПОДКЛЮЧЕНИИ:"
        MSG_YGG_ADDRESS="Адрес Yggdrasil: "
        MSG_PORT="Порт: "
        MSG_USERNAME="Имя пользователя: "
        MSG_PASSWORD="Пароль: "
        MSG_FULL_COMMAND="Полная команда подключения: ssh "
        MSG_INSTALL_COMPLETE="Установка завершена успешно!"
        MSG_SECURE_TUNNEL_ACTIVE="Безопасный туннель теперь активен через сеть Yggdrasil."
        MSG_ENTER_SSH_PORT="Введите порт SSH для использования (по умолчанию: 22): "
        MSG_USING_SSH_PORT="Использование порта SSH: "
        MSG_ASK_CREATE_USER="Вы хотите создать нового пользователя? (д/н): "
        MSG_ENTER_EXISTING_USERNAME="Введите имя существующего пользователя: "
        MSG_USER_NOT_EXISTS="Пользователь не существует"
        MSG_GENERATED_USER="Создан пользователь: "
        MSG_NEW_PASSWORD=" с паролем: "
        MSG_UPDATED_PASSWORD=" с новым паролем: "
        MSG_CONN_INFO_HEADER="==========================================="
        MSG_CONN_INFO_FOOTER="==========================================="
        MSG_CONN_INFO_DETAILS="Адрес Yggdrasil: "
        MSG_CONN_INFO_PORT="Порт: "
        MSG_CONN_INFO_USER="Имя пользователя: "
        MSG_CONN_INFO_PASS="Пароль: "
        MSG_CONN_INFO_CMD="Полная команда подключения: ssh "
    fi
}

# Print colored output
print_info() {
    echo -e "${BLUE}${MSG_INFO}${NC} $1"
}

print_success() {
    echo -e "${GREEN}${MSG_SUCCESS}${NC} $1"
}

print_warning() {
    echo -e "${YELLOW}${MSG_WARNING}${NC} $1"
}

print_error() {
    echo -e "${RED}${MSG_ERROR}${NC} $1"
}

# Check if running as root
check_root() {
    if [[ $EUID -eq 0 ]]; then
        print_error "$MSG_ROOT_ERROR"
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

    print_info "${MSG_DETECTED_OS}$OS ($DISTRO $VER)"

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
        print_error "$MSG_UNSUPPORTED_PKG"
        exit 1
    fi

    print_info "${MSG_PKG_MANAGER}$PKG_MANAGER"
}

# Install dependencies
install_dependencies() {
    print_info "$MSG_INSTALLING_DEPS"

    # Install required packages
    $INSTALL_CMD curl wget gnupg

    # Check if yggdrasil is available in repos
    if ! command -v yggdrasil >/dev/null 2>&1; then
        print_info "$MSG_YGG_NOT_FOUND"

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
                print_error "${MSG_UNSUPPORTED_ARCH}$ARCH"
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

    print_success "$MSG_DEPS_INSTALLED"
}

# Configure firewall rules
configure_firewall() {
    print_info "$MSG_CONFIG_FIREWALL"

    # Detect firewall type
    if command -v iptables >/dev/null 2>&1; then
        FIREWALL_TYPE="iptables"
    elif command -v nft >/dev/null 2>&1; then
        FIREWALL_TYPE="nftables"
    elif command -v ufw >/dev/null 2>&1; then
        FIREWALL_TYPE="ufw"
    else
        print_warning "$MSG_NO_FIREWALL"
        return 0
    fi

    print_info "${MSG_FIREWALL_TYPE}$FIREWALL_TYPE"

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

    print_success "${MSG_FIREWALL_CONFIGURED}$SSH_PORT"
}

# Start yggdrasil service
setup_yggdrasil() {
    print_info "$MSG_SETUP_YGG"

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

    print_success "$MSG_YGG_SERVICE_STARTED"
}

# Configure SSH for Yggdrasil interface
configure_ssh() {
    print_info "$MSG_CONFIG_SSH"

    # Backup original config
    sudo cp /etc/ssh/sshd_config /etc/ssh/sshd_config.backup

    # Modify SSH config to listen on yggdrasil interface
    # First get yggdrasil IP
    YGG_IP=$(yggdrasilctl getSelf | grep -oE '([0-9a-fA-F]{1,4}:){7}[0-9a-fA-F]{1,4}|([0-9]{1,3}\\.){3}[0-9]{1,3}' | head -1)

    if [ -z "$YGG_IP" ]; then
        print_error "$MSG_CANNOT_GET_YGG_IP"
        exit 1
    fi

    # Update SSH config to bind to yggdrasil interface
    sudo sed -i.bak '/^#*ListenAddress/d' /etc/ssh/sshd_config
    echo "ListenAddress $YGG_IP" | sudo tee -a /etc/ssh/sshd_config

    # Set SSH port
    sudo sed -i.bak "s/^#*Port .*/Port $SSH_PORT/" /etc/ssh/sshd_config

    # Restart SSH service
    sudo systemctl restart sshd

    print_success "${MSG_SSH_CONFIGURED}$YGG_IP:$SSH_PORT"
}

# Create or use existing user
manage_user() {
    print_info "$MSG_MANAGE_USER"

    while true; do
        read -p "$MSG_ASK_CREATE_USER" yn
        case $yn in
            [Yy]* )
                CREATE_NEW_USER=true
                break
                ;;
            [Nn]* )
                CREATE_NEW_USER=false
                break
                ;;
            * ) echo "$MSG_PLEASE_ANSWER";;
        esac
    done

    if [ "$CREATE_NEW_USER" = true ]; then
        # Generate random username
        USERNAME="omguser$(openssl rand -hex 4)"
        PASSWORD=$(openssl rand -base64 12)

        # Create user
        sudo useradd -m -s /bin/bash "$USERNAME"
        echo "$USERNAME:$PASSWORD" | sudo chpasswd

        print_success "${MSG_GENERATED_USER}$USERNAME${MSG_NEW_PASSWORD}$PASSWORD"
    else
        # Use existing user
        read -p "$MSG_ENTER_EXISTING_USERNAME" USERNAME

        if ! id "$USERNAME" &>/dev/null; then
            print_error "${MSG_USER_NOT_EXISTS} $USERNAME"
            exit 1
        fi

        # Generate temporary password
        PASSWORD=$(openssl rand -base64 12)
        echo "$USERNAME:$PASSWORD" | sudo chpasswd

        print_success "${MSG_USING_EXISTING_USER}$USERNAME${MSG_UPDATED_PASSWORD}$PASSWORD"
    fi

    # Get yggdrasil IP again to make sure it's available
    YGG_IP=$(yggdrasilctl getSelf | grep -oE '([0-9a-fA-F]{1,4}:){7}[0-9a-fA-F]{1,4}|([0-9]{1,3}\\.){3}[0-9]{1,3}' | head -1)

    # Display connection information
    echo ""
    echo "$MSG_CONN_INFO_HEADER"
    echo "$MSG_CONNECTION_INFO"
    echo "${MSG_YGG_ADDRESS}$YGG_IP"
    echo "${MSG_PORT}$SSH_PORT"
    echo "${MSG_USERNAME}$USERNAME"
    echo "${MSG_PASSWORD}$PASSWORD"
    echo "${MSG_FULL_COMMAND}$USERNAME@$YGG_IP -p $SSH_PORT"
    echo "$MSG_CONN_INFO_FOOTER"
    echo ""
}

# Main execution
main() {
    print_info "$MSG_STARTING_INSTALL"

    check_root
    detect_os

    # Ask user for SSH port
    read -p "$MSG_ENTER_SSH_PORT" SSH_PORT_INPUT
    SSH_PORT=${SSH_PORT_INPUT:-22}

    print_info "${MSG_USING_SSH_PORT}$SSH_PORT"

    install_dependencies
    setup_yggdrasil
    configure_firewall
    configure_ssh
    manage_user

    print_success "$MSG_INSTALL_COMPLETE"
    print_info "$MSG_SECURE_TUNNEL_ACTIVE"
}

# Select language and load messages
select_language
load_messages

# Run main function
main "$@"
