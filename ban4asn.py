#!/usr/bin/env python3
from __future__ import annotations
import os
import sys
import json
import argparse
import subprocess
import platform
import shutil
from shutil import which
from typing import List, Optional

# third-party check (we'll auto-install requests on Debian if missing when applying)
try:
    import requests
except Exception:
    requests = None  # may be installed later

# ---------------- Metadata & endpoints ----------------
ASCII = r"""
__________    _____    _______      _____    _____    _________ _______   
\______   \  /  _  \   \      \    /  |  |  /  _  \  /   _____/ \      \  
 |    |  _/ /  /_\  \  /   |   \  /   |  |_/  /_\  \ \_____  \  /   |   \ 
 |    |   \/    |    \/    |    \/    ^   /    |    \/        \/    |    \
 |______  /\____|__  /\____|__  /\____   |\____|__  /_______  /\____|__  /
        \/         \/         \/      |__|        \/        \/         \/ 
"""
VERSION = "BAN4ASN Tool v0.0.1P"

HACKERTARGET = "https://api.hackertarget.com/aslookup/?q={query}&output=json"
IPAPI_AS = "https://api.ipapi.is/?q=AS{asn}"
IPAPI_WHOIS = "https://api.ipapi.is/?whois=AS{asn}"
RIPE = "https://stat.ripe.net/data/announced-prefixes/data.json?resource=AS{asn}"

LOCAL_NFT = "ban4asn.nft"
DEBIAN_SCRIPT = "setup_nftables.sh"
CLI_INSTALL_DIR = "/usr/local/share/ban4asn"
CLI_PY = os.path.join(CLI_INSTALL_DIR, "ban4asn.py")
CLI_WRAPPER = "/usr/local/bin/ban4asn-cli"
NFT_TABLE_NAME = "ban4asn"

# ---------------- Helpers ----------------
def is_debian() -> bool:
    return os.path.exists("/etc/debian_version")

def safe_input(prompt: str = "") -> str:
    try:
        return input(prompt)
    except KeyboardInterrupt:
        print()
        return ""

def run_cmd(cmd: List[str], capture: bool = True, check: bool = False) -> subprocess.CompletedProcess:
    if capture:
        return subprocess.run(cmd, stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True, check=check)
    else:
        return subprocess.run(cmd, check=check)

def nft_available() -> bool:
    return which("nft") is not None

def require_root(quiet: bool = False) -> bool:
    if os.name == "nt":
        return True
    try:
        if os.geteuid() == 0:
            return True
        if not quiet:
            print("[!] This operation requires root. Re-run with sudo.")
        return False
    except AttributeError:
        return True

# ---------------- HTTP helpers ----------------
def ensure_requests_installed_debian():
    """On Debian, ensure python3-pip and requests package installed via pip3 if missing."""
    global requests
    if requests is not None:
        return True
    # try import again
    try:
        import importlib
        importlib.invalidate_caches()
        requests = __import__("requests")
        return True
    except Exception:
        pass
    # attempt to install via pip3
    print("[i] 'requests' not found. Attempting to install python3-pip and requests via apt/pip3 (Debian)...")
    if not is_debian():
        print("[!] Non-Debian: please install 'requests' manually: pip3 install requests")
        return False
    if not require_root():
        return False
    # ensure pip
    run_cmd(["apt-get", "update"], capture=False)
    run_cmd(["apt-get", "install", "-y", "python3-pip", "ca-certificates"], capture=False)
    # pip3 install requests
    rc = run_cmd(["pip3", "install", "requests"])
    if rc.returncode == 0:
        try:
            import importlib
            importlib.invalidate_caches()
            requests = __import__("requests")
            print("[+] 'requests' installed.")
            return True
        except Exception:
            print("[!] Installed requests but import failed.")
            return False
    else:
        print("[!] pip3 install requests failed:", rc.stderr)
        return False

def http_get_json(url: str) -> Optional[dict]:
    global requests
    if requests is None:
        # best-effort: try to import or request install on Debian
        if is_debian():
            ok = ensure_requests_installed_debian()
            if not ok:
                return None
        else:
            print("[!] 'requests' not available. Install with pip3 install requests")
            return None
    try:
        r = requests.get(url, timeout=20)
        r.raise_for_status()
        return r.json()
    except Exception as e:
        print(f"[!] HTTP GET failed for {url}: {e}")
        return None

def http_get_text(url: str) -> Optional[str]:
    global requests
    if requests is None:
        if is_debian():
            ok = ensure_requests_installed_debian()
            if not ok:
                return None
        else:
            print("[!] 'requests' not available. Install with pip3 install requests")
            return None
    try:
        r = requests.get(url, timeout=30)
        r.raise_for_status()
        return r.text
    except Exception as e:
        print(f"[!] HTTP GET failed for {url}: {e}")
        return None

def hackertarget_lookup(q: str) -> Optional[dict]:
    return http_get_json(HACKERTARGET.format(query=q))

def ipapi_as(asn: str) -> Optional[dict]:
    return http_get_json(IPAPI_AS.format(asn=asn))

def ipapi_whois(asn: str) -> Optional[str]:
    return http_get_text(IPAPI_WHOIS.format(asn=asn))

def ripe_prefixes(asn: str) -> Optional[dict]:
    return http_get_json(RIPE.format(asn=asn))

# ---------------- Formatting & nft generation ----------------
def pretty_asn_info(data: Optional[dict]):
    if not data:
        print("[!] No ASN metadata available.")
        return
    print("\n--- ASN INFORMATION ---")
    for label, key in [("ASN", "asn"), ("Org", "org"), ("Descr", "descr"), ("Country", "country"),
                       ("Type", "type"), ("Domain", "domain"), ("Abuse", "abuse"), ("RIR", "rir"),
                       ("Created", "created"), ("Updated", "updated")]:
        print(f"{label:8}: {data.get(key)}")
    prefixes = data.get("prefixes") or []
    prefixes_v6 = data.get("prefixesIPv6") or []
    print(f"Prefixes (v4): {len(prefixes)}   Prefixes (v6): {len(prefixes_v6)}")
    if prefixes:
        print("Sample v4 (up to 8):")
        for p in prefixes[:8]:
            print(" -", p)
    if prefixes_v6:
        print("Sample v6 (up to 6):")
        for p in prefixes_v6[:6]:
            print(" -", p)
    print("------------------------\n")

def generate_nft_text(prefixes: List[str], table_name: str = NFT_TABLE_NAME) -> str:
    lines = [
        "# Generated by BAN4ASN Tool",
        f"table inet {table_name} {{",
        "    chain input {",
        "        type filter hook input priority 0;",
        "        policy accept;",
        "",
    ]
    for p in prefixes:
        if ":" in p:
            lines.append(f"        ip6 saddr {p} drop")
        else:
            lines.append(f"        ip saddr {p} drop")
    lines.extend([
        "    }",
        "}",
    ])
    return "\n".join(lines)

def write_text_file(path: str, text: str) -> str:
    try:
        with open(path, "w", encoding="utf-8") as fh:
            fh.write(text)
        print(f"[+] Wrote file: {path}")
        return path
    except Exception as e:
        print(f"[!] Failed to write {path}: {e}")
        raise

# ---------------- Debian dependency installation ----------------
def ensure_debian_dependencies():
    """
    Installs: nftables, curl, whois, python3, python3-pip, ca-certificates
    Requires root.
    """
    if not is_debian():
        print("[!] Not Debian; skipping dependency install.")
        return True
    if not require_root():
        return False
    print("[i] Updating apt and installing dependencies: nftables, curl, whois, python3, python3-pip, ca-certificates")
    try:
        run_cmd(["apt-get", "update"], capture=False)
        run_cmd(["apt-get", "install", "-y", "nftables", "curl", "whois", "python3", "python3-pip", "ca-certificates"], capture=False)
        print("[+] apt installation finished.")
        # ensure requests
        ensure_requests_installed_debian()
        return True
    except Exception as e:
        print("[!] Apt install failed:", e)
        return False

# ---------------- Debian installer script builder ----------------
def build_debian_installer(nft_source_path: str, script_path: str = DEBIAN_SCRIPT) -> str:
    installer = f"""#!/usr/bin/env bash
set -e
if [[ $EUID -ne 0 ]]; then
  echo "Run as root"
  exit 1
fi

echo "[+] Installing dependencies..."
apt-get update -y
apt-get install -y nftables curl whois python3 python3-pip ca-certificates

echo "[+] Copying nft file..."
mkdir -p /etc/nftables
cp "{nft_source_path}" /etc/nftables/{NFT_TABLE_NAME}.nft

echo "[+] Applying rules..."
nft -f /etc/nftables/{NFT_TABLE_NAME}.nft

echo "[+] Creating /etc/nftables.conf that includes the ban file..."
cat >/etc/nftables.conf <<'EOF'
#!/usr/sbin/nft -f
flush ruleset
include "/etc/nftables/{NFT_TABLE_NAME}.nft"
EOF

echo "[+] Enabling nftables service..."
systemctl enable nftables
systemctl restart nftables

echo "[✓] nftables configured and ban applied."
"""
    try:
        write_text_file(script_path, installer)
        os.chmod(script_path, 0o755)
        print(f"[+] Debian installer script created: {script_path}")
        return script_path
    except Exception as e:
        print("[!] Failed to create Debian installer:", e)
        raise

# ---------------- apply / unblock operations ----------------
def apply_nft_file(path: str) -> bool:
    if not nft_available():
        print("[!] 'nft' not in PATH.")
        return False
    if not require_root():
        return False
    try:
        proc = run_cmd(["nft", "-f", path])
        if proc.returncode == 0:
            print("[+] nft rules applied.")
            return True
        else:
            print("[!] nft returned non-zero. stderr:")
            print(proc.stderr.strip())
            return False
    except Exception as e:
        print("[!] Error running nft:", e)
        return False

def delete_nft_table(table_name: str = NFT_TABLE_NAME) -> bool:
    if not nft_available():
        print("[!] 'nft' not in PATH.")
        return False
    if not require_root():
        return False
    try:
        proc = run_cmd(["nft", "delete", "table", "inet", table_name])
        if proc.returncode == 0:
            print("[+] Deleted table:", table_name)
            return True
        else:
            print("[!] nft delete failed. stderr:")
            print(proc.stderr.strip())
            return False
    except Exception as e:
        print("[!] Exception deleting table:", e)
        return False

# ---------------- CLI wrapper install ----------------
def install_cli_wrapper(copy_script_instead: bool = True):
    """Install CLI wrapper on Debian. Copies script to CLI_INSTALL_DIR and creates wrapper."""
    if not is_debian():
        print("[!] CLI wrapper installation intended for Debian-like systems.")
        return
    if not require_root():
        return
    try:
        os.makedirs(CLI_INSTALL_DIR, exist_ok=True)
        src = os.path.abspath(sys.argv[0])
        if copy_script_instead:
            # copy file to CLI_INSTALL_DIR
            dest = CLI_PY
            shutil.copy2(src, dest)
            os.chmod(dest, 0o755)
            print(f"[+] Copied script to {dest}")
        else:
            dest = src
        wrapper = f"""#!/usr/bin/env bash
exec python3 "{dest}" "$@"
"""
        write_text_file(CLI_WRAPPER, wrapper)
        os.chmod(CLI_WRAPPER, 0o755)
        print(f"[+] Installed wrapper: {CLI_WRAPPER} -> runs {dest}")
        print("[+] You can now run: ban4asn-cli lookup 8.8.8.8")
    except Exception as e:
        print("[!] Failed to install CLI wrapper:", e)

# ---------------- Interactive flows ----------------
def interactive_lookup():
    q = safe_input("Enter IP or prefix (8.8.8.8 or 8.8.8.0/24): ").strip()
    if not q:
        print("Aborted.")
        return
    print("[i] Querying HackerTarget...")
    ht = hackertarget_lookup(q)
    if not ht:
        print("[!] HackerTarget lookup failed.")
        return
    asn = ht.get("asn")
    print(f"[i] ASN: {asn} ({ht.get('asn_name')})")
    info = ipapi_as(asn)
    pretty_asn_info(info)
    while True:
        c = safe_input("[w]hois / [b]ack: ").lower().strip()
        if c.startswith("w"):
            who = ipapi_whois(asn)
            if who:
                print("\n--- WHOIS ---\n")
                print(who)
                print("\n--- END WHOIS ---\n")
            else:
                print("[!] No WHOIS text.")
        else:
            break

def interactive_ban():
    q = safe_input("Enter IP/prefix or ASN (8.8.8.8 or 8.8.8.0/24 or AS15169): ").strip()
    if not q:
        print("Aborted.")
        return
    if q.upper().startswith("AS"):
        asn = q[2:]
    elif q.isdigit():
        asn = q
    else:
        ht = hackertarget_lookup(q)
        if not ht:
            print("[!] Lookup failed.")
            return
        asn = ht.get("asn")
    print(f"[i] Using ASN: {asn}")
    ripe = ripe_prefixes(asn)
    if not ripe:
        print("[!] RIPE lookup failed.")
        return
    prefixes = [entry["prefix"] for entry in ripe.get("data", {}).get("prefixes", [])]
    if not prefixes:
        print("[!] No prefixes found.")
        return
    print("\nAnnounced prefixes:")
    for p in prefixes:
        print(" -", p)
    print("\nOptions:")
    print("1) Generate .nft file only (local)")
    print("2) Create Debian installer script (requires Debian)")
    print("3) Generate & apply now (installs deps on Debian if needed)")
    print("4) Cancel")
    choice = safe_input("Select (1-4): ").strip()
    nft_text = generate_nft_text(prefixes)
    if choice == "1":
        path = write_text_file(LOCAL_NFT, nft_text)
        print(f"[i] To apply manually: sudo nft -f {path}")
    elif choice == "2":
        if not is_debian():
            print("[!] Debian installer only supported on Debian.")
            return
        path = write_text_file(LOCAL_NFT, nft_text)
        script = build_debian_installer(path, DEBIAN_SCRIPT)
        print(f"[i] Run: sudo bash {script}")
    elif choice == "3":
        # If Debian: install deps first
        path = write_text_file(LOCAL_NFT, nft_text)
        if is_debian():
            ok = ensure_debian_dependencies()
            if not ok:
                print("[!] Failed to install dependencies.")
                return
        if not nft_available():
            print("[!] nft command not found even after installing; abort.")
            return
        if not require_root():
            return
        applied = apply_nft_file(path)
        if applied:
            print("[✓] Rules applied.")
    else:
        print("Cancelled.")

def interactive_unblock():
    if not nft_available():
        print("[!] nft not available.")
        return
    if not require_root():
        return
    ok = delete_nft_table(NFT_TABLE_NAME)
    if not ok:
        print(f"[!] Could not delete table. Manual: sudo nft delete table inet {NFT_TABLE_NAME}")

def interactive_install_cli():
    if not is_debian():
        print("[!] CLI wrapper installation is intended for Debian systems.")
        return
    if not require_root():
        return
    install_cli_wrapper(copy_script_instead=True)

def interactive_instructions():
    print(f"""
BAN4ASN Tool {VERSION} - Instructions

- Use 'lookup' to get ASN for an IP/prefix and metadata
- Use 'ban' to generate a nft file for an ASN's announced prefixes
- Debian only: choose 'apply now' and the tool will:
    * install dependencies (nftables, python3-pip, curl, whois, ca-certificates)
    * install python requests via pip3 if missing
    * apply generated nft rules
- Install CLI wrapper (Debian): copies script to {CLI_PY} and creates {CLI_WRAPPER}
- Unblock removes the nft table named: {NFT_TABLE_NAME}
Files created locally:
 - {LOCAL_NFT}
 - {DEBIAN_SCRIPT}
""")

# ---------------- CLI command implementations ----------------
def cmd_lookup(target: str):
    ht = hackertarget_lookup(target)
    if not ht:
        print("[!] hackertarget lookup failed.")
        return
    asn = ht.get("asn")
    print(f"[i] ASN: {asn} ({ht.get('asn_name')})")
    info = ipapi_as(asn)
    pretty_asn_info(info)

def cmd_ban(target: str, apply_now: bool = False, debian_installer: bool = False):
    if target.upper().startswith("AS"):
        asn = target[2:]
    elif target.isdigit():
        asn = target
    else:
        ht = hackertarget_lookup(target)
        if not ht:
            print("[!] hackertarget lookup failed.")
            return
        asn = ht.get("asn")
    print(f"[i] ASN: {asn}")
    ripe = ripe_prefixes(asn)
    if not ripe:
        print("[!] RIPE lookup failed.")
        return
    prefixes = [entry["prefix"] for entry in ripe.get("data", {}).get("prefixes", [])]
    if not prefixes:
        print("[!] No prefixes.")
        return
    nft_text = generate_nft_text(prefixes)
    nft_path = write_text_file(LOCAL_NFT, nft_text)
    if debian_installer:
        if not is_debian():
            print("[!] Debian installer is only supported on Debian-like systems.")
        else:
            script = build_debian_installer(nft_path, DEBIAN_SCRIPT)
            print(f"[i] Created Debian installer: {script}")
    if apply_now:
        if is_debian():
            ok = ensure_debian_dependencies()
            if not ok:
                print("[!] Failed to install dependencies.")
                return
        if not nft_available():
            print("[!] nft not in PATH; aborting apply.")
            return
        if not require_root():
            return
        applied = apply_nft_file(nft_path)
        if applied:
            print("[✓] Applied rules.")

def cmd_generate(target: str, debian_installer: bool = False):
    cmd_ban(target, apply_now=False, debian_installer=debian_installer)

def cmd_unblock():
    if not nft_available():
        print("[!] nft not found.")
        return
    if not require_root():
        return
    ok = delete_nft_table(NFT_TABLE_NAME)
    if not ok:
        print("[!] Manual: sudo nft delete table inet", NFT_TABLE_NAME)

def cmd_install_cli():
    if not is_debian():
        print("[!] CLI wrapper installation is intended for Debian systems.")
        return
    if not require_root():
        return
    install_cli_wrapper(copy_script_instead=True)

# ---------------- Argparse ----------------
def build_arg_parser():
    parser = argparse.ArgumentParser(prog="ban4asn", description="BAN4ASN Tool (interactive if no args).")
    sub = parser.add_subparsers(dest="cmd", help="subcommands")

    p_lookup = sub.add_parser("lookup", help="Lookup IP or prefix")
    p_lookup.add_argument("target", help="IP or prefix")

    p_ban = sub.add_parser("ban", help="Ban ASN or IP/prefix")
    p_ban.add_argument("target", help="ASN or IP/prefix")
    p_ban.add_argument("--apply-now", action="store_true", help="Attempt to apply nft rules now (installs deps on Debian)")
    p_ban.add_argument("--debian-installer", action="store_true", help="Create Debian installer script")

    p_gen = sub.add_parser("generate", help="Generate nft file or Debian installer for ASN/IP")
    p_gen.add_argument("target", help="ASN or IP/prefix")
    p_gen.add_argument("--debian-installer", action="store_true", help="Also create Debian installer script")

    sub.add_parser("unblock", help="Remove nft table created by this tool")
    sub.add_parser("install-cli", help="Install CLI wrapper (Debian only)")
    sub.add_parser("instructions", help="Show instructions")
    sub.add_parser("interactive", help="Run interactive menu")

    return parser

# ---------------- Interactive menu ----------------
def interactive_menu():
    while True:
        try:
            os.system("cls" if os.name == "nt" else "clear")
        except Exception:
            pass
        print(ASCII)
        print(VERSION)
        print()
        print("1) Lookup IP/ASN")
        print("2) BAN IP/ASN")
        print("3) Unblock")
        print("4) Instructions")
        print("5) Install CLI wrapper (Debian only)")
        print("6) Exit")
        sel = safe_input("Select (1-6): ").strip()
        if sel == "1":
            interactive_lookup()
            safe_input("Press Enter...")
        elif sel == "2":
            interactive_ban()
            safe_input("Press Enter...")
        elif sel == "3":
            interactive_unblock()
            safe_input("Press Enter...")
        elif sel == "4":
            interactive_instructions()
            safe_input("Press Enter...")
        elif sel == "5":
            interactive_install_cli()
            safe_input("Press Enter...")
        elif sel == "6":
            print("Bye.")
            return
        else:
            print("Invalid choice.")
            safe_input("Press Enter...")

# ---------------- Entrypoint ----------------
def main():
    parser = build_arg_parser()
    if len(sys.argv) == 1:
        interactive_menu()
        return
    args = parser.parse_args()
    cmd = args.cmd
    if cmd == "lookup":
        cmd_lookup(args.target)
    elif cmd == "ban":
        cmd_ban(args.target, apply_now=args.apply_now, debian_installer=args.debian_installer)
    elif cmd == "generate":
        cmd_generate(args.target, debian_installer=args.debian_installer)
    elif cmd == "unblock":
        cmd_unblock()
    elif cmd == "install-cli":
        cmd_install_cli()
    elif cmd == "instructions":
        interactive_instructions()
    elif cmd == "interactive":
        interactive_menu()
    else:
        parser.print_help()

if __name__ == "__main__":
    try:
        main()
    except KeyboardInterrupt:
        print("\nInterrupted. Exiting.")
        sys.exit(0)
