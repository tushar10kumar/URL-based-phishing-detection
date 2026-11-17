# URL-Based Phishing Detection Using Machine Learning

An intelligent cybersecurity system that extracts lexical, structural, and security features from URLs to assess phishing risk degrees (**Safe**, **Low**, **Moderate**, **High**, **Critical**) using a trained Machine Learning model.

---

## 🚀 Features

- **Qualitative Threat Assessment**:
  - Replaces raw probability figures with actionable security degrees:
    - 🟢 **Safe / Minimal Risk**: Verified domain hierarchy, safe protocols, no suspicious patterns.
    - 🟡 **Low Risk**: Minor lexical anomalies with no threat indicators.
    - 🟠 **Moderate Risk**: Multiple risk indicators detected (e.g. nested subdomains, credential keywords).
    - 🔴 **High Risk**: Aggressive phishing patterns identified.
    - 🛑 **Critical Risk**: Confirmed brand spoofing or unauthorized IP targeting.

- **18+ Advanced Extracted URL Features**:
  - Brand Impersonation / Spoofing Check (e.g., `paypal-login.xyz` vs official `paypal.com`)
  - High-Risk Top-Level Domains (`.tk`, `.xyz`, `.top`, `.pw`, etc.)
  - URL Shortener Masking (`bit.ly`, `tinyurl.com`, etc.)
  - Subdomain Depth & Hyphen Patterning
  - Shannon String Entropy & Randomness
  - Contextual Keyword Analysis (Domain vs Path)

- **Trained on Benchmark Multi-Source Dataset (5,370+ URLs)**:
  - PhishTank & UNB academic benchmark
  - OpenPhish live verified attack feeds
  - Major verified root authorities

---

## 📁 Project Structure

```text
url-based-phishing-detection-using-machine-learning/
├── dataset/
│   └── phishing_urls.csv     # Benchmark multi-source dataset
├── static/
│   ├── css/style.css         # Dark-mode cybersecurity UI
│   └── js/main.js            # Dynamic risk ladder visualization
├── templates/
│   └── index.html            # Web dashboard interface
├── feature_extraction.py     # 18+ URL feature extractor
├── generate_dataset.py       # Dataset generator (OpenPhish + UNB)
├── train.py                  # Model training and evaluation script
├── predict.py                # Command-line testing utility
├── app.py                    # Flask web server & REST API
├── run.bat                   # 1-click Windows desktop launcher
├── requirements.txt          # Python dependencies
└── model.pkl                 # Trained Random Forest classifier
```

---

## ⚡ How to Run

### 1. Launch via Web Dashboard (Recommended)
Simply double-click **`run.bat`** or run:
```bash
python app.py
```
Open your browser at:
👉 **`http://127.0.0.1:5000`**

### 2. Test via Command Line (CLI)
```bash
python predict.py "https://www.google.com"
python predict.py "https://appleid.apple.com.verify-billing.tk/login"
```
