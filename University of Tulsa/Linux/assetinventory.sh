#! /bin/bash

# Variables
FLAG=$1


# Text Colors
GREEN='\033[1;32m'
END='\033[0m'

function command_exists() {
    command -v "$1" > /dev/null 2>&1
}

function header() { echo -e "${GREEN}$1${END}" ; }

function usage(){
    programname=$0
    echo "Usage: $programname [option]"
    echo "  -h                  Display Help"
    exit 1
}


function runall() {
    # users()
    software()
    network()
}


# function users() {

# }




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
    header "Linux Asset Inventory Script (Still work in progress)"
    echo "Authors.......: Matthew"
    echo "Version.......: 1.0"
    echo "OS............: $(cat /etc/os-release | awk -F= '/PRETTY_NAME/ {print $2}')"
    echo -e "Executing as user: $CURRENT_USER\n"
fi

# Run Specified Mode
case $FLAG in
        "-e")   runall;;
        "-h")   usage;;
esac