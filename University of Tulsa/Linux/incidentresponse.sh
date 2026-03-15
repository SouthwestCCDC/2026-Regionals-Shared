#! /bin/bash
# Incident Response Script for CCDC
# Sourced some code from CCDC/Hivestorm script written by TNAR5, colonket, ferdinand

# Variables
FLAG=$1


# Text Colors
GREEN='\033[1;32m'
END='\033[0m'

function header() { echo -e "${GREEN}$1${END}" ; }

function info() {
    header "System Uptime: "
    uptime

    header "Active Users:"
    who

    header "Open Ports:"
    netstat -tulnp

    header "Running Processes:"
    ps aux --sort=-%mem | head -n 10

    header "Network Connections:"
    ss -tunap

    header "Sudo Commands:"
    journalctl _COMM=sudo --no-pager | grep "$(date "+%b %d")" | grep -v "session opened" | grep -v "session closed"
}

function command_exists() {
    command -v "$1" > /dev/null 2>&1
}

function logins() {
    header "SSH Logins:"
    journalctl -u ssh --no-pager | grep "$(date "+%b %d")"
}

function software() {

    header "Software Installed:"

    if [[ $DISTRIBUTION == "debian" ]]
        then dpkg --get-selections --no-pager | awk '{print $1}'
    fi

    if [[ $DISTRIBUTION == "redhat" ]]
        # Test the one below still
        then yum list installed | awk '{print $1}'
    fi

    if [[ $DISTRIBUTION == "alpine" ]]
        # Test the one below still
        then apk list --installed | awk -F' ' '{print $1}' | cut -d' ' -f1 | cut -d'-' -f1
    fi

    if [[ $DISTRIBUTION == "freebsd" ]]
        # Test the one below still
        then pkg query "%n"
    fi

    if [[ $DISTRIBUTION == "unsupported" ]]
        # Test the one below still
        then echo "Not supported"
    fi

    header "Outdated Software:"

    if [[ $DISTRIBUTION == "debian" ]]
        then apt list --upgradable
    fi

    if [[ $DISTRIBUTION == "redhat" ]]
        # Test the one below still
        then yum check-update
    fi

    if [[ $DISTRIBUTION == "alpine" ]]
        # Test the one below still
        then apk version -l '<'
    fi

    if [[ $DISTRIBUTION == "freebsd" ]]
        # Test the one below still
        then pkg version -l '<'
    fi

    if [[ $DISTRIBUTION == "unsupported" ]]
        # Test the one below still
        then echo "Not supported"
    fi

}

function usage(){
    programname=$0
    echo "Usage: $programname [option]"
    echo "  -b                  Basic Info Mode"
    echo "  -l                  Check logins"
    echo "  -h                  Display Help"
    echo "  -s                  Display Software Info"
    echo "  -setup              Installed needed packages"
    echo "  -sudo               Find sudo commands given a username"
    exit 1
}

function setup() {
    header "Updating and installing neccessary packages"
    if [[ $DISTRIBUTION == "debian" ]]; then
        apt update
        apt install net-tools
    fi
    
    if [[ $DISTRIBUTION == "redhat" ]]; then
        yum update -y
        yum install net-tools -y
    fi

    if [[ $DISTRIBUTION == "alpine" ]]; then
        apk update
        apk add net-tools
    fi

    if [[ $DISTRIBUTION == "freebsd" ]]; then
        pkg update
        pkg install net-tools
    fi
}

# Find sudo commands via a given username
function sudocommands () {
    header "Sudo commands executed today given a username:"
    echo "Please enter a username:"
    read username
    journalctl _COMM=sudo --no-pager | grep "$(date "+%b %d")" | grep -v "session opened" | grep -v "session closed" | grep "$username"

    # journalctl _COMM=sudo --no-pager | grep "$(date "+%b %d")" | grep -v "session opened" | grep -v "session closed" | grep "matt" | awk '{print $1 " " $2 " " $3 " " $6 " " $14}'
}

# Get distro
if command_exists apt-get; then
    DISTRIBUTION="debian"
elif command_exists yum; then
    DISTRIBUTION="redhat"
elif command_exists apk; then
	DISTRIBUTION="alpine"
elif command_exists pkg; then
	DISTRIBUTION="freebsd"
else
    DISTRIBUTION="unsupported"
fi


if [[ "$FLAG" == "" ]]; then
    FLAG="-h"
fi


# Print Information for Script
if [[ "$FLAG" != "-h" ]]
    then
    if [ "$EUID" -ne 0 ]
        then echo "Please run as root!"
        exit 1
    fi

    CURRENT_USER=$(whoami)
    echo
    header "Linux Incident Response Script"
    echo "Authors.......: Matthew"
    echo "Version.......: 1.1"
    echo "OS............: $(cat /etc/os-release | awk -F= '/PRETTY_NAME/ {print $2}')"
    echo -e "Executing as user: $CURRENT_USER\n"
fi

# Run Specified Mode
case $FLAG in
        "-b")   info;;
        "-l")   logins;;
        "-h")   usage;;
        "-s")   software;;
        "-setup")   setup;;
        "-sudo")    sudocommands;;
esac