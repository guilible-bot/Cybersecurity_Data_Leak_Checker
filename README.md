# Data Breach Checker 🛡️

A desktop application that lets users check whether an IP address or URL is suspicious or malicious using the VirusTotal API. Users can register, log in, save scan history, update their profile, search past scans, and even generate PDF reports — all inside a Tkinter GUI.

## 🔧 Features
- User Registration and Login
- IP & URL threat detection using VirusTotal
- Stores check results locally in SQLite
- Search checks by date
- Profile update
- PDF report generation (using ReportLab)

## 🖼️ UI Preview
(Add a screenshot inside the `assets/` folder and link it like below)

![Preview](assets/preview.png)

---

## ⚙️ Setup Instructions

### 1. Clone this repo
```bash
git clone https://github.com/YOUR_USERNAME/data-breach-checker.git
cd data-breach-checker
```

### 2. Create virtual environment (optional but recommended)
```bash
python -m venv venv
source venv/bin/activate  # Windows: venv\Scripts\activate
```

### 3. Install dependencies
```bash
pip install -r requirements.txt
```

### 4. Add your VirusTotal API Key

Replace the placeholder in `app.py` with your own API key:

```python
API_KEY = "your_api_key_here"
```

You can get one by signing up here: https://www.virustotal.com/

### 5. Run the app
```bash
python app.py
```

---

## 🗃️ Database
Two SQLite tables are created on the first run:
- `users(id, username, password)`
- `checks(id, user_id, ip_address, url, result, timestamp)`

---

## 🧰 Requirements

- Python 3.7+
- `tkinter` (comes with Python)
- `requests`
- `reportlab`

---

## 📄 License
MIT License. Free to use and modify.
