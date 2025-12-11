#!/bin/bash

clear
echo "============================================"
echo "     Ban4ASN Debian Installer"
echo "============================================"
echo ""

INSTALL_DIR="/opt/b4a"

if [ "$EUID" -ne 0 ]; then
    echo "This installer must be run as root."
    exit 1
fi

mkdir -p "$INSTALL_DIR"

echo "Where would you like to download BAN4ASN from?"
echo "1) Alex's GIT (https://git.techotterdev.com/alex/BAN4ASN)"
echo "2) GitHub     (https://github.com/alex/BAN4ASN)"
echo ""
read -p "Select an option (1 or 2): " SOURCE_CHOICE

case "$SOURCE_CHOICE" in
    1)
        REPO_URL="https://git.techotterdev.com/alex/BAN4ASN"
        ;;
    2)
        REPO_URL="https://github.com/alex/BAN4ASN"
        ;;
    *)
        echo "Invalid choice. Exiting."
        exit 1
        ;;
esac

echo ""
echo "[+] Updating package list..."
apt update -y

echo "[+] Installing git..."
apt install -y git

echo "[+] Cloning BAN4ASN repository from:"
echo "    $REPO_URL"
rm -rf "$INSTALL_DIR"
git clone "$REPO_URL" "$INSTALL_DIR"

chmod -R 755 "$INSTALL_DIR"

echo ""
echo "============================================"
echo " Ban4ASN installed to: $INSTALL_DIR"
echo "============================================"
echo ""
echo "To run the Python tool:"
echo "    python3 $INSTALL_DIR/ban4asn.py"
echo ""
echo "Installation complete."
