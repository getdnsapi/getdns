#!/bin/bash
# Stubby helper file to set DNS servers on OSX.
# Must run as root.

usage () {
    echo
    echo "Update the system DNS resolvers so that Stubby is used for all DNS"
    echo "queries. (Stubby must already be running)"
    echo "This must be run as root, and is currently only supported on MAC OS X."
    echo
    echo "Usage: $0 options"
    echo
    echo "Supported options:"
    echo "  -r Reset DNS resolvers to the default ones (e.g. from DHCP)"
    echo "  -l List the current DNS settings for all interfaces"
    echo "  -h Show this help."
}

RESET=0
LIST=0
SERVERS="127.0.0.1 ::1"
OS_X=`uname -a | grep -c 'Darwin'`

while getopts ":rlh" opt; do
    case $opt in
        r  ) RESET=1 ;;
        l  ) LIST=1 ;;
        h  ) usage
             exit 1 ;;
        \? ) usage
             exit 1 ;;
    esac
done


if [[ $OS_X -eq 0 ]]; then
    echo "Sorry - This script is currenlty only supported on MAC OS X."
    exit 1
fi

if [[ $LIST -eq 1 ]]; then
    echo "** Current DNS settings **"
    networksetup -listallnetworkservices 2>/dev/null | grep -v '*' | while read x ; do
        RESULT=`networksetup -getdnsservers "$x"`
        RESULT=`echo $RESULT`
        printf '%-30s %s\n' "$x:" "$RESULT"
    done
    exit 1
fi

if [ "$USER" != "root" ]; then
    echo "Must be root to update system resolvers. Retry using 'sudo stubby-setdns'"
    exit 1
fi

if [[ $RESET -eq 1 ]]; then
    SERVERS="empty"
    echo "Setting DNS servers to '"$SERVERS"' - the system will use default DNS service."
else
    echo "Setting DNS servers to '"$SERVERS"' - the system will use Stubby if it is running."
fi

### Set the DNS settings via networksetup ###
networksetup -listallnetworkservices 2>/dev/null | grep -v '*' | while read x ; do
    networksetup -setdnsservers "$x" $SERVERS
done

