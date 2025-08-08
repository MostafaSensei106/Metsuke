
# 🛡️ File Hash Analyzer & Threat Intelligence Tool

A Python-based GUI tool (built with `tkinter`) for **file analysis, hash calculation, and threat intelligence lookups** using **VirusTotal** and **Hybrid Analysis** APIs.

---

## 🚀 Features
- **File Hashing**: Calculate SHA-256 hash for any file.
- **Threat Intelligence Lookup**:
  - Search file hashes on **VirusTotal**.
  - Search file hashes on **Hybrid Analysis**.
- **Export Results**:
  - Save search results to text files.
- **Clipboard Support** *(optional)*: Copy results directly to your clipboard.
- **GUI Enhancements**:
  - Modern, user-friendly interface.
  - Organized results with scrollable text boxes.
- **Notifications / Alerts**:
  - Inform the user if the file is clean, suspicious, or malicious.
  - Error handling for invalid input or API issues.

---

---

## ⚙️ Requirements
- Python 3.8+
- Install dependencies:
```bash
pip install requests pyperclip
```
*(Remove `pyperclip` if clipboard support is not needed)*

---

## 🔑 API Keys
This tool requires:
- **VirusTotal API Key** → [Get it here](https://developers.virustotal.com/reference/api-overview)
- **Hybrid Analysis API Key** → [Get it here](https://www.hybrid-analysis.com/docs/api/v2)

Add your keys inside the script:
```python
VIRUSTOTAL_API_KEY = "your_api_key_here"
HYBRID_ANALYSIS_API_KEY = "your_api_key_here"
```

---

## 🖥️ Usage
Run the script:
```bash
python file_hash_analyzer.py
```
1. Select a file.
2. Click **"Scan Hash on VirusTotal"**.
3. View results in the GUI or export them.

---

## 📌 Future Enhancements
- Multi-file batch analysis.
- Support for more threat intelligence platforms (e.g., AlienVault OTX, AbuseIPDB).
- Dark mode UI theme.
- Automatic hash type detection.
- Real-time alerts from APIs.

---

## 📜 License
This project is licensed under the MIT License – you are free to use, modify, and distribute it.

---

## 🤝 Contributing
Pull requests are welcome. For major changes, please open an issue first to discuss your idea.

---

**Author:** Ahmed Emad Eldeen  (Odo)  
**GitHub:** [[Your GitHub Profile Link](https://github.com/Eng-Ahmed-Emad)]
