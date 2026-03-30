🛰️ Advanced Subdomain Recon Tool (Python)
A high-speed, multi-source subdomain reconnaissance tool built in Python. It aggregates intelligence from multiple sources, validates DNS, and performs live HTTP/HTTPS checks — all in parallel.
Think of it as a digital разведчик (scout) that maps the hidden surface of a domain 🌐

🚀 Features
	•	⚡ Parallel Multi-Source Enumeration
	◦	Brute-force
	◦	Certificate Transparency (crt.sh)
	◦	AlienVault OTX
	◦	Wayback Machine
	◦	GitHub (basic scraping)
	◦	VirusTotal (optional API)
	◦	SecurityTrails (optional API)
	•	🌐 DNS Resolution Filtering
	◦	Identifies valid subdomains
	•	🔎 Alive Check (HTTP/HTTPS)
	◦	HTTPS first, then HTTP fallback
	◦	Captures status codes (200, 403, etc.)
	•	💾 Dual Output Files
	◦	all_subdomains.txt → all discovered
	◦	live_subdomains.txt → only active hosts
	•	⚙️ Portable & Path-Independent
	◦	Works from any directory
	◦	Saves output in script location
	•	⏱️ Timeout Controlled (30s)
	◦	Prevents hanging requests

🧰 Tech Stack
	•	Python 3.x
	•	requests
	•	socket (built-in)
	•	concurrent.futures

📦 Installation
Clone the repository:

git https://github.com/krishankr1/subdomain_scanner.git
cd subdomain-recon-tool

Install dependencies:

pip3 install requests


▶️ Usage
Run the tool:

python3 subdomain_scanner.py -d example.com

Or interactive mode:

python3 subdomain_scanner.py


📁 Output
After execution, two files are generated:
1️⃣ All Discovered Subdomains

all_subdomains.txt

Example:

api.example.com
dev.example.com
staging.example.com


2️⃣ Live Subdomains (HTTP/HTTPS Responding)

live_subdomains.txt

Example:

www.example.com -> https://www.example.com [200]
api.example.com -> http://api.example.com [403]


🧠 How It Works

[ Sources ]
   ↓
Aggregate Subdomains
   ↓
Remove Duplicates
   ↓
DNS Resolution Check
   ↓
HTTP/HTTPS Alive Check
   ↓
Save Results


🔑 Optional API Configuration
To unlock more sources, add your API keys inside the script:

VT_API_KEY = "your_virustotal_key"
ST_API_KEY = "your_securitytrails_key"


⚠️ Notes
	•	Some sources may be slow or rate-limited
	•	GitHub search may require authentication for better results
	•	Wayback results are limited for performance
	•	macOS users may see:  NotOpenSSLWarning               This is harmless and does not affect functionality

🛠️ Customization Ideas
	•	Add larger wordlists (SecLists)
	•	Integrate more APIs (Shodan, Censys)
	•	Add JSON/CSV output
	•	Implement async scanning
	•	Add screenshot capture

⚠️ Disclaimer
This tool is intended for:
	•	✅ Educational purposes
	•	✅ Authorized security testing
Do NOT use against targets without permission.

🧭 Roadmap
	•	⚡ Async engine (faster than threading)
	•	📊 Structured output (JSON)
	•	🌐 HTTP probing enhancements
	•	🎯 Subdomain takeover detection
	•	📸 Visual recon (screenshots)

🤝 Contributing
Pull requests are welcome. Ideas, improvements, and optimizations are encouraged.

⭐ Support
If this tool helped you, consider giving it a ⭐ on GitHub. It helps others discover it and keeps development alive.
