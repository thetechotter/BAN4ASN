# BAN4ASN

[![License: MIT](https://img.shields.io/badge/License-MIT-green.svg)](https://opensource.org/licenses/MIT)
![Platform](https://img.shields.io/badge/Platform-Cross--Platform-blue)
![Language](https://img.shields.io/badge/Python-3.8%2B-yellow)
![Status](https://img.shields.io/badge/Status-Active-brightgreen)
![Debian](https://img.shields.io/badge/OS-Debian_Optimized-red)
![CLI](https://img.shields.io/badge/CLI-Supported-purple)
![nftables](https://img.shields.io/badge/nftables-Automation-orange)

---

## 📌 Overview

**BAN4ASN** is a powerful, cross‑platform security tool that allows administrators to:

- Identify the ASN for any IP, prefix, or ASN number  
- Retrieve live prefix announcements from RIPE  
- Automatically generate nftables firewall rules to block entire ASNs  
- Deploy rules automatically on Debian systems  
- Install a standalone CLI binary for automated operations  
- Unblock previously applied rules  
- Use the tool across Windows, macOS, and Linux  
- Enjoy fast, dependency‑free operation except for Python and `requests`

Developed and maintained by **TechOtter**, licensed under the **MIT License**.

---

## 🚀 Features

### 🔍 Lookup features
- IP → ASN lookup via HackerTarget API  
- ASN metadata resolution via ipapi.is  
- WHOIS querying  
- RIPE Stat prefix enumeration  

### 🔒 Security / Blocking
- Generate nftables `.nft` rule files  
- Auto‑setup mode for Debian:
  - Installs all dependencies  
  - Configures nftables  
  - Places rules in `/etc/nftables/ban4asn.nft`  
  - Enables persistent system service  
  - Immediately applies drop rules  

### 🧹 Unblocking
- Removes the entire nftables `ban4asn` table cleanly  
- Supported in Python mode and CLI binary mode  

### 🖥️ Cross‑Platform Python Application
- Works on:
  - Windows (CMD/PowerShell)
  - Linux (all major distros)
  - macOS  
- Debian gets special automation capabilities

### 🏗️ Optional Debian CLI Installer
- Generates a binary‑like command: `ban4asn-cli`  
- Allows full control without running the Python service  
- Supports ban, unblock, lookup, and rule deployment  

---

## 📦 Installation

### 🔧 Requirements
- Python **3.8+**
- `pip install requests`

---

## 🐧 Debian Installation with Auto‑Installer

You can install BAN4ASN using the included `.sh` installation script:

```
bash install_b4a.sh
```

You will be asked to select a source mirror:

```
Please select a mirror:
1. GitHub
2. TechOtter CDN (Germany)
```

### Mirror behavior

#### **1. GitHub mirror**
- Installs `git` automatically
- Clones:
  https://github.com/thetechotter/BAN4ASN/
- Installs to:  
  `/opt/b4a/`

#### **2. TechOtter CDN mirror**
- Installs `unzip`
- Downloads archive:
  https://c.techotterdev.com/tools/b4a/ban4asn.zip
- Extracts into:
  `/opt/b4a/`

CLI and system paths are set automatically.

---

## 🧰 Usage Guide

### Launch the Python Tool
```
python3 ban4asn.py
```

### Lookup Example
```
1) Lookup IP/ASN
Enter 1.1.1.1
View WHOIS, ASN, prefixes, etc.
```

### Create a nftables rule file
```
2) BAN
Select:
1) Generate .nft file
```

### Debian Auto‑Deploy Mode
```
2) BAN
Select:
2) Auto‑Install + Deploy nftables
```

Automatically:
- Installs nftables
- Creates rule file
- Enables nftables system service
- Applies block instantly

### Unblock
```
3) Unblock
```

Removes full `ban4asn` nftables table.

---

## 🧪 CLI Binary Usage (Debian Only)

Once installed:
```
ban4asn-cli lookup 8.8.8.8
ban4asn-cli ban AS13335
ban4asn-cli auto-ban AS32934
ban4asn-cli unblock
```

---

## 📂 Project Structure

```
ban4asn.py                → Main cross‑platform service
ban4asn.nft               → Generated rule file (only when banning)
setup_nftables.sh         → Auto-deploy script (Debian only)
ban4asn-cli               → Optional CLI binary-like wrapper
install_b4a.sh            → Debian installer script
README.md / README.txt    → Documentation
```

---

## 📝 License

This project is licensed under the **MIT License**.  
Created by **TechOtter**.

---

## ❤️ Support / Contributions

Contributions are welcome!  
Fork the project, submit PRs, or contact TechOtter for feature requests.

