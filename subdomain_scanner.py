#!/usr/bin/env python3

import socket
import requests
import argparse
import os
from concurrent.futures import ThreadPoolExecutor, as_completed

# ================= CONFIG =================
SUBDOMAINS = ["www","mail","ftp","dev","api","test","staging","beta","admin"]

VT_API_KEY = ""
ST_API_KEY = ""

TIMEOUT = 30

SCRIPT_DIR = os.path.dirname(os.path.abspath(__file__))
ALL_FILE = os.path.join(SCRIPT_DIR, "all_subdomains.txt")
LIVE_FILE = os.path.join(SCRIPT_DIR, "live_subdomains.txt")

HEADERS = {"User-Agent": "ReconTool/3.0"}

# ================= CORE =================

def resolve(domain):
    try:
        socket.gethostbyname(domain)
        return True
    except:
        return False


def check_alive(domain):
    urls = [f"https://{domain}", f"http://{domain}"]

    for url in urls:
        try:
            r = requests.get(url, timeout=TIMEOUT, headers=HEADERS)
            return f"{domain} -> {url} [{r.status_code}]"
        except:
            continue

    return None

# ---------- SOURCES ----------

def brute_force(domain):
    print("[*] Brute-force")
    return {f"{sub}.{domain}" for sub in SUBDOMAINS}


def crtsh(domain):
    print("[*] crt.sh")
    found = set()
    try:
        r = requests.get(f"https://crt.sh/?q=%25.{domain}&output=json", timeout=TIMEOUT)
        for entry in r.json():
            for sub in entry['name_value'].split("\n"):
                if domain in sub:
                    found.add(sub.strip())
    except Exception as e:
        print(f"[!] crt.sh error: {e}")
    return found


def otx(domain):
    print("[*] OTX")
    found = set()
    try:
        url = f"https://otx.alienvault.com/api/v1/indicators/domain/{domain}/passive_dns"
        r = requests.get(url, timeout=TIMEOUT)
        for entry in r.json().get("passive_dns", []):
            host = entry.get("hostname")
            if host and domain in host:
                found.add(host)
    except:
        pass
    return found


def wayback(domain):
    print("[*] Wayback")
    found = set()
    try:
        url = f"http://web.archive.org/cdx/search/cdx?url=*.{domain}&output=json&fl=original"
        r = requests.get(url, timeout=TIMEOUT)
        data = r.json()[1:300]

        for entry in data:
            sub = entry[0].split("/")[2]
            if domain in sub:
                found.add(sub)
    except:
        pass
    return found


def github(domain):
    print("[*] GitHub")
    found = set()
    try:
        url = f"https://api.github.com/search/code?q={domain}"
        r = requests.get(url, timeout=TIMEOUT)

        if r.status_code == 200:
            for item in r.json().get("items", [])[:20]:
                name = item.get("name", "")
                if domain in name:
                    found.add(name)
    except:
        pass
    return found


def virustotal(domain):
    if not VT_API_KEY:
        return set()

    print("[*] VirusTotal")
    found = set()
    try:
        url = f"https://www.virustotal.com/api/v3/domains/{domain}/subdomains"
        r = requests.get(url,
                         headers={"x-apikey": VT_API_KEY},
                         timeout=TIMEOUT)

        for item in r.json().get("data", []):
            found.add(item["id"])
    except:
        pass
    return found


def securitytrails(domain):
    if not ST_API_KEY:
        return set()

    print("[*] SecurityTrails")
    found = set()
    try:
        url = f"https://api.securitytrails.com/v1/domain/{domain}/subdomains"
        r = requests.get(url,
                         headers={"apikey": ST_API_KEY},
                         timeout=TIMEOUT)

        for sub in r.json().get("subdomains", []):
            found.add(f"{sub}.{domain}")
    except:
        pass
    return found


# ================= MAIN =================

def main():
    parser = argparse.ArgumentParser(description="Advanced Recon Tool")
    parser.add_argument("-d", "--domain", help="Target domain")
    args = parser.parse_args()

    domain = args.domain or input("Enter domain: ").strip()

    print(f"\n🚀 Recon started for: {domain}\n")

    sources = [
        brute_force,
        crtsh,
        otx,
        wayback,
        github,
        virustotal,
        securitytrails
    ]

    all_subs = set()

    # Run sources in parallel
    with ThreadPoolExecutor(max_workers=7) as executor:
        futures = {executor.submit(src, domain): src.__name__ for src in sources}

        for future in as_completed(futures):
            name = futures[future]
            try:
                results = future.result()
                print(f"[+] {name} → {len(results)} found")
                all_subs.update(results)
            except Exception as e:
                print(f"[!] {name} failed: {e}")

    print(f"\n[*] Total discovered: {len(all_subs)}")

    # Save ALL subdomains
    with open(ALL_FILE, "w") as f:
        for sub in sorted(all_subs):
            f.write(sub + "\n")

    print(f"[💾] Saved all subdomains → {ALL_FILE}")

    # Filter resolvable first
    print("\n[*] Checking DNS resolution...\n")

    resolvable = set()
    with ThreadPoolExecutor(max_workers=50) as executor:
        futures = {executor.submit(resolve, sub): sub for sub in all_subs}

        for future in as_completed(futures):
            sub = futures[future]
            if future.result():
                resolvable.add(sub)

    print(f"[+] Resolvable: {len(resolvable)}")

    # Alive check
    print("\n[*] Checking alive domains (HTTP/HTTPS)...\n")

    live_results = set()
    with ThreadPoolExecutor(max_workers=30) as executor:
        futures = {executor.submit(check_alive, sub): sub for sub in resolvable}

        for future in as_completed(futures):
            result = future.result()
            if result:
                print(f"[+] {result}")
                live_results.add(result)

    # Save LIVE
    with open(LIVE_FILE, "w") as f:
        for line in sorted(live_results):
            f.write(line + "\n")

    print(f"\n✅ Live domains saved → {LIVE_FILE}")


if __name__ == "__main__":
    main()
