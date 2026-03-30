#!/usr/bin/env python3

import socket
import requests
import argparse
import os
from concurrent.futures import ThreadPoolExecutor, as_completed

# ================= CONFIG =================
SUBDOMAINS = ["www","mail","ftp","dev","api","test","staging","beta","admin"]

VT_API_KEY = ""   # optional
ST_API_KEY = ""   # optional

TIMEOUT = 30

SCRIPT_DIR = os.path.dirname(os.path.abspath(__file__))
OUTPUT_FILE = os.path.join(SCRIPT_DIR, "recon_results.txt")

HEADERS = {"User-Agent": "ReconTool/2.0"}

# ================= CORE =================

def resolve(domain):
    try:
        ip = socket.gethostbyname(domain)
        return f"{domain} -> {ip}"
    except:
        return None

# ---------- Sources ----------

def brute_force(domain):
    print("[*] Brute-force started")
    found = set()
    for sub in SUBDOMAINS:
        full = f"{sub}.{domain}"
        found.add(full)
    return found


def crtsh(domain):
    print("[*] crt.sh")
    found = set()
    try:
        r = requests.get(f"https://crt.sh/?q=%25.{domain}&output=json",
                         timeout=TIMEOUT)
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
    except Exception as e:
        print(f"[!] OTX error: {e}")
    return found


def wayback(domain):
    print("[*] Wayback")
    found = set()
    try:
        url = f"http://web.archive.org/cdx/search/cdx?url=*.{domain}&output=json&fl=original"
        r = requests.get(url, timeout=TIMEOUT)

        data = r.json()[1:300]  # skip header + limit
        for entry in data:
            sub = entry[0].split("/")[2]
            if domain in sub:
                found.add(sub)

    except Exception as e:
        print(f"[!] Wayback error: {e}")
    return found


def github(domain):
    print("[*] GitHub")
    found = set()
    try:
        url = f"https://api.github.com/search/code?q={domain}"
        r = requests.get(url, timeout=TIMEOUT)

        if r.status_code != 200:
            return found

        for item in r.json().get("items", [])[:20]:
            name = item.get("name", "")
            if domain in name:
                found.add(name)

    except Exception as e:
        print(f"[!] GitHub error: {e}")
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

    except Exception as e:
        print(f"[!] VT error: {e}")

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

    except Exception as e:
        print(f"[!] ST error: {e}")

    return found


# ================= MAIN =================

def main():
    parser = argparse.ArgumentParser(description="Fast Subdomain Recon Tool")
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

    # 🔥 Run all sources in parallel
    with ThreadPoolExecutor(max_workers=7) as executor:
        future_to_source = {
            executor.submit(src, domain): src.__name__ for src in sources
        }

        for future in as_completed(future_to_source):
            name = future_to_source[future]
            try:
                results = future.result()
                print(f"[+] {name} → {len(results)} found")
                all_subs.update(results)
            except Exception as e:
                print(f"[!] {name} failed: {e}")

    print(f"\n[*] Total collected before resolution: {len(all_subs)}")

    # 🔥 Resolve in parallel
    print("\n[*] Resolving live domains...\n")

    final_results = set()

    with ThreadPoolExecutor(max_workers=50) as executor:
        futures = [executor.submit(resolve, sub) for sub in all_subs]

        for future in as_completed(futures):
            result = future.result()
            if result:
                print(f"[+] {result}")
                final_results.add(result)

    # Save
    with open(OUTPUT_FILE, "w") as f:
        for line in sorted(final_results):
            f.write(line + "\n")

    print(f"\n✅ Done. Saved to: {OUTPUT_FILE}")


if __name__ == "__main__":
    main()
