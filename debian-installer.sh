#!/bin/bash

clear
echo "============================================"
echo "     Ban4ASN Debian Installer"
echo "============================================"
echo ""
echo "Please select a mirror:"
echo "1. GitHub"
echo "2. TechOtter CDN (Germany)"
echo ""
read -rp "Enter option (1 or 2): " MIRROR

INSTALL_DIR="/opt/b4a"

if [ "$EUID" -ne 0 ]; then
    echo "This installer must be run as root."
    exit 1
fi

mkdir -p "$INSTALL_DIR"

apt update -y

case "$MIRROR" in
    1)
        echo "Installing from GitHub..."
        apt install -y git
        rm -rf "$INSTALL_DIR"
        git clone https://github.com/thetechotter/BAN4ASN/ "$INSTALL_DIR"
        ;;

    2)
        echo "Installing from TechOtter CDN..."
        apt install -y wget unzip
        rm -rf "$INSTALL_DIR"
        mkdir -p "$INSTALL_DIR"
        wget -O /tmp/ban4asn.zip https://c.techotterdev.com/tools/b4a/ban4asn.zip
        unzip /tmp/ban4asn.zip -d "$INSTALL_DIR"
        rm /tmp/ban4asn.zip
        ;;

    *)
        echo "Invalid choice."
        exit 1
        ;;
esac

chmod -R 755 "$INSTALL_DIR"

echo ""
echo "============================================"
echo " Ban4ASN installed to: $INSTALL_DIR"
echo "============================================"
echo ""
echo "To run the Python tool:"
echo "    python3 $INSTALL_DIR/ban4asn.py"
echo ""
echo "If a CLI binary is included, it is located in:"
echo "    $INSTALL_DIR/bin/"
echo ""
echo "Installation complete."
