🛰️ Elite Subdomain Recon Tool
A powerful Python-based reconnaissance tool designed for subdomain discovery, enumeration, and takeover detection using multiple intelligence sources.
This tool combines active + passive recon techniques, integrates external tools, and includes automatic binary setup, making it a portable and efficient red teaming utility.

🚀 Features
	•	🔍 Subdomain Enumeration (Brute-force + Passive)
	•	🌐 Multi-source Recon:
	◦	crt.sh (Certificate Transparency)
	◦	Subfinder (auto-install supported)
	◦	Amass (auto-install supported)
	•	⚡ Fast Multithreaded DNS Resolution
	•	🔥 Subdomain Takeover Detection
	•	🌐 Optional Alive Host Detection (HTTP status)
	•	📊 JSON Output Support (for automation pipelines)
	•	🧰 Self-bootstrapping tool installer (Subfinder + Amass)

🧰 Requirements
	•	Python 3.8+
	•	macOS or Linux (tested)
Python Dependencies:
Install required modules:
pip3 install requests dnspython

⚙️ Installation
Clone the repository:
git clone https://github.com/krishankr1/subdomain_scanner.git
cd subdomain-recon

▶️ Usage
🔹 Basic Scan
python3 subdomain_scanner.py -d example.com

🔹 Scan with Alive Host Detection
python3 subdomain_scanner.py -d example.com --alive

🔹 Export Results in JSON
python3 subdomain_scanner.py -d example.com --json

📁 Output
Results are saved in the same directory as the script:
	•	recon_results.txt (default)
	•	recon_results.json (if --json is used)

🧠 How It Works
	1	Performs brute-force subdomain guessing
	2	Queries crt.sh for passive discovery
	3	Uses Subfinder & Amass (auto-installed if missing)
	4	Resolves subdomains to IP addresses
	5	Detects potential takeover vulnerabilities
	6	Saves results locally

🔥 Subdomain Takeover Detection
The tool checks for common misconfigurations in services like:
	•	GitHub Pages
	•	AWS S3
	•	Heroku
	•	Azure
	•	CloudFront
	•	Fastly
⚠️ Note: Detection is heuristic-based. Always verify manually.

⚠️ Disclaimer
This tool is intended for:
	•	Educational purposes
	•	Authorized security testing only
Do NOT use this tool on systems without explicit permission.

🛠️ Optional (Recommended Setup)
For better stability, install tools manually:
brew install amass
brew install subfinder

🚀 Future Improvements
	•	Async scanning (performance boost)
	•	Screenshot automation
	•	Subdomain permutation engine
	•	Takeover auto-verification
	•	Proxy / stealth mode
	•	Web dashboard interface

🤝 Contributing
Contributions are welcome. Feel free to submit pull requests or suggest improvements.

⭐ Support
If you find this tool useful, consider giving it a ⭐ on GitHub.

👨‍💻 Author
Developed for recon, red teaming, and learning purposes.
