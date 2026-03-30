#!/usr/bin/env python3

import socket
import requests
import argparse
import os
import subprocess
import shutil
import zipfile
import json
import dns.resolver
from concurrent.futures import ThreadPoolExecutor

# ------------------ CONFIG ------------------
SCRIPT_DIR = os.path.dirname(os.path.abspath(__file__))
OUTPUT_FILE = os.path.join(SCRIPT_DIR, "recon_results.txt")
TOOLS_DIR = os.path.join(SCRIPT_DIR, "tools")
os.makedirs(TOOLS_DIR, exist_ok=True)

DEFAULT_SUBDOMAINS = [
    "www","mail","ftp","api","dev","test","admin","portal","vpn",
    "blog","staging","beta","shop","secure","cdn","auth","gateway",
    "internal","dashboard","app","docs","status","media","static"
]

TAKEOVER_SIGNATURES = {
    "github.io": "There isn't a GitHub Pages site here.",
    "herokuapp.com": "No such app",
    "amazonaws.com": "NoSuchBucket",
    "azurewebsites.net": "404 Web Site not found",
    "cloudfront.net": "ERROR: The request could not be satisfied",
    "fastly.net": "Fastly error: unknown domain"
}

# ------------------ UTIL ------------------
def is_installed(tool):
    return shutil.which(tool) is not None

def download(url, path):
    try:
        headers = {"User-Agent": "Mozilla/5.0"}
        r = requests.get(url, headers=headers, stream=True, timeout=25)

        if r.status_code != 200:
            raise Exception(f"HTTP {r.status_code}")

        with open(path, "wb") as f:
            for chunk in r.iter_content(8192):
                f.write(chunk)

        if not zipfile.is_zipfile(path):
            raise Exception("Downloaded file is not a valid zip")

    except Exception as e:
        print(f"[!] Download failed: {e}")
        if os.path.exists(path):
            os.remove(path)
        return False

    return True

# ------------------ AUTO INSTALL ------------------
def install_subfinder():
    if is_installed("subfinder"):
        return "subfinder"

    print("[*] Installing Subfinder...")
    url = "https://github.com/projectdiscovery/subfinder/releases/latest/download/subfinder_2.6.6_macOS_amd64.zip"
    zip_path = os.path.join(TOOLS_DIR, "subfinder.zip")

    if not download(url, zip_path):
        return None

    try:
        with zipfile.ZipFile(zip_path, "r") as z:
            z.extractall(TOOLS_DIR)
    except:
        print("[!] Extraction failed (Subfinder)")
        return None

    binary = os.path.join(TOOLS_DIR, "subfinder")
    os.chmod(binary, 0o755)
    return binary

def install_amass():
    if is_installed("amass"):
        return "amass"

    print("[*] Installing Amass...")
    url = "https://github.com/owasp-amass/amass/releases/latest/download/amass_darwin_amd64.zip"
    zip_path = os.path.join(TOOLS_DIR, "amass.zip")

    if not download(url, zip_path):
        return None

    try:
        with zipfile.ZipFile(zip_path, "r") as z:
            z.extractall(TOOLS_DIR)
    except:
        print("[!] Extraction failed (Amass)")
        return None

    binary = os.path.join(TOOLS_DIR, "amass")
    os.chmod(binary, 0o755)
    return binary

# ------------------ SOURCES ------------------
def crtsh(domain):
    found = set()
    try:
        r = requests.get(f"https://crt.sh/?q=%25.{domain}&output=json", timeout=15)
        for entry in r.json():
            for sub in entry.get("name_value","").split("\n"):
                if domain in sub:
                    found.add(sub.strip())
    except:
        pass
    return found

def subfinder(domain):
    binary = install_subfinder()
    if not binary:
        print("[!] Skipping Subfinder")
        return set()

    try:
        r = subprocess.run([binary, "-d", domain, "-silent"], capture_output=True, text=True)
        return set(r.stdout.splitlines())
    except:
        return set()

def amass(domain):
    binary = install_amass()
    if not binary:
        print("[!] Skipping Amass")
        return set()

    found = set()
    try:
        r = subprocess.run([binary, "enum", "-d", domain], capture_output=True, text=True)
        for line in r.stdout.splitlines():
            if domain in line:
                found.add(line.strip())
    except:
        pass

    return found

def brute(domain):
    found = set()
    with ThreadPoolExecutor(max_workers=40) as ex:
        futures = [ex.submit(resolve, f"{s}.{domain}") for s in DEFAULT_SUBDOMAINS]
        for f in futures:
            r = f.result()
            if r:
                found.add(r.split(" -> ")[0])
    return found

# ------------------ RESOLVE ------------------
def resolve(host):
    try:
        ip = socket.gethostbyname(host)
        return f"{host} -> {ip}"
    except:
        return None

def is_alive(host):
    try:
        r = requests.get(f"http://{host}", timeout=3)
        return r.status_code
    except:
        return None

# ------------------ TAKEOVER ------------------
def get_cname(subdomain):
    try:
        answers = dns.resolver.resolve(subdomain, "CNAME")
        for rdata in answers:
            return str(rdata.target).strip(".")
    except:
        return None

def check_takeover(subdomain):
    cname = get_cname(subdomain)
    if not cname:
        return None

    for service, signature in TAKEOVER_SIGNATURES.items():
        if service in cname:
            try:
                r = requests.get(f"http://{subdomain}", timeout=5)
                if signature in r.text:
                    return f"[VULNERABLE] {subdomain} → {service}"
            except:
                pass

    return None

# ------------------ MAIN ------------------
def main():
    parser = argparse.ArgumentParser(description="Elite Recon Tool (Stable)")
    parser.add_argument("-d","--domain")
    parser.add_argument("--alive", action="store_true")
    parser.add_argument("--json", action="store_true")

    args = parser.parse_args()
    domain = args.domain or input("Enter domain: ").strip()

    print(f"\n[*] Recon started for {domain}\n")

    subs = set()
    subs |= brute(domain)
    subs |= crtsh(domain)
    subs |= subfinder(domain)
    subs |= amass(domain)

    print(f"[*] Total collected: {len(subs)}")

    results = []

    for s in subs:
        r = resolve(s)
        if r:
            print(f"[+] {r}")

            entry = {"host": s, "ip": r.split(" -> ")[1]}

            if args.alive:
                status = is_alive(s)
                if status:
                    entry["status"] = status
                    print(f"    ↳ HTTP {status}")

            takeover = check_takeover(s)
            if takeover:
                entry["takeover"] = True
                print(f"🔥 {takeover}")

            results.append(entry)

    if args.json:
        with open(OUTPUT_FILE.replace(".txt",".json"), "w") as f:
            json.dump(results, f, indent=2)
    else:
        with open(OUTPUT_FILE, "w") as f:
            for r in results:
                f.write(f"{r['host']} -> {r['ip']}\n")

    print("\n[✔] Done")

if __name__ == "__main__":
    main()