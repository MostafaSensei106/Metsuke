# 🛡️ Malware Hash Scanner - GUI Tool

A lightweight, beginner-friendly Python-based GUI tool for extracting file hashes (SHA-256) and scanning them directly against **VirusTotal** and **Hybrid Analysis**. Designed for SOC Analysts, Malware Researchers, and Threat Hunters.

---

## 📸 Screenshots

![screenshot](screenshot.png) <!-- Replace with your screenshot if available -->

---

## 🔍 Features

- ✅ **File Hashing**: Instantly computes SHA-256 hash of any selected file (image, document, executable, etc).
- 🧠 **Threat Lookup**: Searches the calculated hash on:
  - [VirusTotal](https://www.virustotal.com/gui/home/search)
  - [Hybrid Analysis](https://www.hybrid-analysis.com/)
- 🖥️ **Simple GUI**: Intuitive interface built using Python `tkinter`.
- 🔐 **Offline Support**: Hash calculation works offline; only the lookups need internet access.
- 🔒 **API Key Support**: Integrates your own API keys securely.

---

## 🧰 Requirements

- Python 3.6 or newer
- Modules:
  - `requests`
  - `tkinter` (usually preinstalled with Python)

Install dependencies via pip:

```bash
pip install requests
```

---

## 🚀 Usage

1. Clone the repository or download the source code.
2. Open terminal/cmd in the project folder.
3. Run the tool:

```bash
python malware_scanner.py
```

---

## 💻 Build EXE (Optional)

You can convert the script into a standalone Windows `.exe` using **PyInstaller**:

### 🔧 Step-by-Step

1. Install PyInstaller:

```bash
pip install pyinstaller
```

2. Build the EXE with icon:

```bash
pyinstaller --onefile --windowed --icon=icon.ico malware_scanner.py
```

3. The `.exe` file will be located in the `dist` folder.

---

## 📌 Use Cases

- SOC triage automation
- Malware hash verification
- Incident response support
- Threat hunting enrichment
- Reverse engineering preparation

---

## 🔐 API Keys

Make sure to replace the `api_key` variables in the script with your own API keys from:

- [VirusTotal API](https://developers.virustotal.com/reference/overview)
- [Hybrid Analysis API](https://www.hybrid-analysis.com/docs/api/v2/overview)

---

## 🌍 Future Enhancements

- Submit unknown files to VirusTotal directly.
- Display scan result verdicts inside GUI in a clean format.
- JSON report export.
- Integration with more sandboxes (AnyRun, Joe Sandbox, etc).
- Dark mode theme.

---

## 👨‍💻 Author

Built with 💙 by **Ahmed Emad (Odo)**  
Security Analyst | Cloud & SOC Specialist

[GitHub](https://github.com/ahmedemad) • [LinkedIn](https://www.linkedin.com/in/ahmedemad/) • [Portfolio](https://eng-ahmed-emad.github.io/AhmedEmad-Dev/)

---

## 📝 License

This project is licensed under the MIT License.