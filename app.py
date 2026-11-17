"""
Flask Web Application for URL-Based Phishing Detection.
Categorizes URLs into Qualitative Risk Degrees (Critical, High, Moderate, Low, Safe).
"""

import os
from flask import Flask, render_template, request, jsonify
from predict import predict_url, load_trained_model

app = Flask(__name__)

# Preload trained model on startup
print("[*] Initializing Phishing Detection Model...")
load_trained_model()
print("[+] Ready to accept predictions.")

SAMPLE_URLS = [
    {"label": "Legitimate (Google Search)", "url": "https://www.google.com/search?q=cybersecurity"},
    {"label": "Legitimate (GitHub Login)", "url": "https://github.com/login"},
    {"label": "Legitimate (PayPal Signin)", "url": "https://www.paypal.com/signin"},
    {"label": "Phishing (Spoofed Apple ID)", "url": "https://appleid.apple.com.verify-billing.tk/login"},
    {"label": "Phishing (Fake PayPal Hyphen)", "url": "https://secure-paypal-login.xyz/webscr"},
    {"label": "Phishing (Direct IP Address)", "url": "http://192.168.1.100/paypal/login.php"},
    {"label": "Phishing (URL Shortener)", "url": "http://tinyurl.com/secure-login-chase-update"}
]

def format_risk_factors(features: dict) -> list:
    """Returns human-readable explanation of detected risk indicators."""
    factors = []
    if features.get('brand_spoofed'):
        factors.append({
            "title": "Brand Impersonation / Spoofing Detected",
            "desc": "Hostname mimics a well-known brand (e.g. PayPal, Apple, Google, Chase) on an unauthorized root domain.",
            "severity": "danger"
        })
    if features.get('having_ip'):
        factors.append({
            "title": "Raw IP Address Used",
            "desc": "The URL uses a raw IP address instead of a standard verified domain name.",
            "severity": "danger"
        })
    if features.get('suspicious_tld'):
        factors.append({
            "title": "High-Risk Top-Level Domain (TLD)",
            "desc": "Registered under a disposable TLD heavily linked to malicious activity (.tk, .xyz, .top, etc.).",
            "severity": "danger"
        })
    if features.get('shortening_service'):
        factors.append({
            "title": "URL Shortener Masking",
            "desc": "Uses a link-shortening redirect service to conceal the true destination URL.",
            "severity": "warning"
        })
    if features.get('having_at'):
        factors.append({
            "title": "'@' Symbol in URL",
            "desc": "Browser ignores characters before '@', often used to display a fraudulent brand prefix.",
            "severity": "danger"
        })
    if features.get('prefix_suffix'):
        factors.append({
            "title": "Hyphen in Domain Name",
            "desc": "Hyphens in domain names are frequently used to combine trusted names with attack terms (e.g., secure-paypal.com).",
            "severity": "warning"
        })
    if features.get('has_keywords_in_domain'):
        factors.append({
            "title": "Authentication Keywords in Domain",
            "desc": "Domain includes credential-harvesting keywords (login, verify, secure, banking).",
            "severity": "warning"
        })
    if features.get('has_excessive_subdomains'):
        factors.append({
            "title": "Excessive Subdomain Levels",
            "desc": "Multiple nested subdomains used to mimic legitimate URL hierarchies.",
            "severity": "warning"
        })
    if features.get('url_entropy', 0) > 4.2:
        factors.append({
            "title": "High String Entropy",
            "desc": "High randomness detected, indicative of algorithmically generated domain tokens.",
            "severity": "info"
        })
    if features.get('is_trusted_domain'):
        factors.append({
            "title": "Verified Legitimate Authority",
            "desc": "Root domain matches an officially recognized global authority.",
            "severity": "safe"
        })
    return factors

@app.route('/')
def home():
    return render_template('index.html', samples=SAMPLE_URLS)

@app.route('/api/predict', methods=['POST'])
def api_predict():
    data = request.get_json(silent=True) or request.form
    url = data.get('url', '').strip()

    if not url:
        return jsonify({"error": "No URL provided."}), 400

    try:
        result = predict_url(url)
        factors = format_risk_factors(result['features'])
        result['risk_factors'] = factors
        return jsonify(result)
    except Exception as e:
        return jsonify({"error": str(e)}), 500

@app.route('/api/samples', methods=['GET'])
def api_samples():
    return jsonify(SAMPLE_URLS)

if __name__ == '__main__':
    print("\n=======================================================")
    print("   URL-Based Phishing Detection System")
    print("   Web server running at: http://127.0.0.1:5000")
    print("=======================================================\n")
    app.run(host='127.0.0.1', port=5000, debug=True)
