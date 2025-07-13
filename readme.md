# 🔍 Threat Hash & IP Enricher (Chrome Extension)

A powerful  Chrome Extension built to assist SOC analysts and cybersecurity engineers in enriching file hashes and IP addresses using multiple threat intelligence platforms such as **VirusTotal**, **Hybrid Analysis**, **AlienVault OTX**, and **AbuseIPDB**.  

This tool provides fast, consolidated threat context directly in the browser—ideal for triaging incidents in platforms like **Microsoft Sentinel**, **Splunk**, or **Elastic**.

---

## ✨ Features

- ✅ **File Hash Lookup** (SHA256)
  - VirusTotal: detection ratio, AV vendors
  - Hybrid Analysis: verdicts, MITRE ATT&CK, indicators
  - AlienVault OTX: community reputation, pulses

- ✅ **IP Address Lookup**
  - VirusTotal: ASN, country, detection, vendors
  - AbuseIPDB: abuse confidence, category classification, recent reports

- 🎨 **Professional UI**:
  - Dark mode, responsive layout
  - Colored badges for threat level
  - Elegant cards with per-entry separation

- 📋 **Copy All**:
  - One-click button to copy all results in a structured format for SOC alert comments.

---

## 🛠 Technologies Used

- **JavaScript (ES6 modules)**
- **Chrome Extension (Manifest V3)**
- **CryptoJS** for AES API key encryption
- **Hybrid Analysis**, **VirusTotal**, **AbuseIPDB**, **AlienVault OTX** APIs
- **Tailwind-inspired custom CSS** for layout and theme

---

## 🧠 How It Works

1. User pastes a file hash or IP address
2. Extension determines the type (IP vs hash)
3. Sends requests to backend services via `background.js`
4. Results are parsed, rendered into cards, and displayed
5. "Copy All" aggregates all results into formatted text for pasting

---

## ⚙️ Setup & Installation

1. **Clone or Download** this repository.

2. **Load as Unpacked Extension:**
   - Open Chrome → `chrome://extensions`
   - Enable **Developer Mode**
   - Click **Load Unpacked** → Select the project folder

3. **Configure API Keys** (hardcoded or encrypted):
   - Replace `apiKey` fields in:
     - `virustotal.js`
     - `abuseipdb.js`
     - `alienvault.js`
     - `hybrid-analysis.js`

4. **Encryption of API Keys:**
   - API keys are AES-encrypted inside `background.js`
   - Uses `CryptoJS` with shared passphrase to decrypt
   - Proxy enabled via `thingproxy` or `corsproxy` to bypass CORS

---

## 🧬 Overall Flow
User Input (IP or Hash)
    ↓
popup.js → Determine Input Type (IP / Hash)
    ↓
Trigger lookups (via lookup-button.js)
    ↓
Each API module (e.g. virustotal.js, abuseipdb.js) formats and sends message
    ↓
background.js intercepts and performs `fetch()` via a CORS proxy
    ↓
Response decrypted and parsed
    ↓
Each module renders results into clean result cards in popup
    ↓
Optional: copy-all-button.js formats results into structured plain text


---

## 🧩 Example Output (Copy All) For IP

#IP :
VirusTotal
IP: 185.143.222.17
Country: FR
ASN: 26383

Analysis: 3 malicious / 94 total

Detected By:
- alphaMountain.ai: suspicious [suspicious]

- AlphaSOC: suspicious [suspicious]

- CINS Army: malicious [malicious]

- Fortinet: malware [malicious]

- SOCRadar: suspicious [suspicious]

- ThreatHive: malicious [malicious]

---

AbuseIPDB
IP: 185.143.222.17
Type: Public IP
Confidence of Abuse: 100%
Reports Count: 39 Times
Last Report: 13-07-2025
Category: Port Scan, Brute-Force


## 🧩 Example Output (Copy All) For Hash

#Hash :
VirusTotal:
File Name: 😱 НЕУЖЕЛИ ПУКИН - ХУЙЛО❓ 😭
Detections: 3 / 76
Malicious Vendors:- Webroot: W32.Malware.Gen

- Xcitium: Packed.Win32.MUPX.Gen@24tbus

- MaxSecure: Trojan.Malware.300983.susgen

---

AlienVault OTX:
Score: Not available
Pulses: 0
AV Detections (0):

YARA Detections (0):

Alerts (0):

---

Hybrid Analysis:
Report 1:
File Name: PingInfoView.chm
State: no specific threat
Environment: Windows 10 64 bit
Analysis Time: 22-01-2025
Threat Score: 0
AV Detection: 0%
File Type: text, mshelp, 27351 bytes


Malicious Indicators:
- Unusual Characteristics
 : Entrypoint in PE header is within an uncommon section

- Unusual Characteristics
 : Imports suspicious APIs

- Anti-Reverse Engineering
 : section contains high entropy

- Anti-Reverse Engineering
 : PE file is packed with UPX

- Spyware/Information Retrieval
 : Found system commands related strings

- Spyware/Information Retrieval
 : Calls an API typically used for keylogging

- Network Related
 : Contains ability to identify remote systems

- System Security
 : Writes registry keys

- System Destruction
 : Opens file with deletion access rights

- External Systems
 : Sample detected by CrowdStrike Static Analysis and ML with relatively low confidence




Report 2:
File Name: PingInfoView.exe
State: suspicious
Environment: Windows 10 64 bit
Analysis Time: 22-01-2025
Threat Score: 72
AV Detection: 2%
File Type: peexe, executable, 62464 bytes

No suspicious or malicious indicators found in this report.



Report 3:
File Name: Unknown file
State: -
Environment: Windows 10 64 bit
Analysis Time: NaN-NaN-NaN
Threat Score: 0
AV Detection: 0%
File Type: text, 22748 bytes

No suspicious or malicious indicators found in this report.

---

## 🔐 Security Note

- **No external server used**. All API calls and logic stay on the client via `background.js`.
- API keys are encrypted using AES. You must still treat the extension as semi-private or obfuscate sensitive logic for production deployment.

---

## 🧑‍💻 Developer Notes

To edit API keys:
- Store them encrypted with `CryptoJS.AES.encrypt(...)`
- Modify `background.js` to match your proxy and decryption logic
- Avoid committing raw keys into the codebase

---

## 🤝 Acknowledgements

- [VirusTotal Public API](https://developers.virustotal.com/)
- [Hybrid Analysis API](https://www.hybrid-analysis.com/docs/api/v2/)
- [AbuseIPDB API](https://docs.abuseipdb.com/)
- [AlienVault OTX](https://otx.alienvault.com/)
- [CryptoJS](https://github.com/brix/crypto-js)
