"""
CLI Prediction Tool for URL-Based Phishing Detection.
Categorizes URLs into Risk Degrees (Critical, High, Moderate, Low, Safe)
without exposing raw percentage figures.
"""

import sys
import os
import joblib
import pandas as pd
from feature_extraction import extract_features, FEATURE_NAMES

MODEL_PATH = os.path.join(os.path.dirname(__file__), "model.pkl")

def load_trained_model():
    if not os.path.exists(MODEL_PATH):
        print("[-] Trained model not found! Training now...")
        from train import train_phishing_model
        train_phishing_model()
    return joblib.load(MODEL_PATH)

def calculate_risk_degree(phishing_prob: float, features: dict) -> dict:
    """Maps continuous risk probabilities and critical indicators to discrete risk degrees."""
    # Critical override for confirmed brand spoofing or known IP abuse
    if features.get('brand_spoofed') == 1:
        return {
            'level': 'Critical',
            'label': 'CRITICAL RISK',
            'verdict': 'Phishing',
            'is_phishing': True,
            'color': 'danger'
        }

    if features.get('is_trusted_domain') == 1 and not features.get('brand_spoofed'):
        return {
            'level': 'Safe',
            'label': 'SAFE / LEGITIMATE',
            'verdict': 'Legitimate',
            'is_phishing': False,
            'color': 'safe'
        }

    if phishing_prob >= 80.0:
        return {
            'level': 'High',
            'label': 'HIGH RISK',
            'verdict': 'Phishing',
            'is_phishing': True,
            'color': 'danger'
        }
    elif phishing_prob >= 50.0:
        return {
            'level': 'Moderate',
            'label': 'MODERATE RISK',
            'verdict': 'Suspicious',
            'is_phishing': True,
            'color': 'warning'
        }
    elif phishing_prob >= 20.0:
        return {
            'level': 'Low',
            'label': 'LOW RISK',
            'verdict': 'Legitimate',
            'is_phishing': False,
            'color': 'low'
        }
    else:
        return {
            'level': 'Safe',
            'label': 'SAFE / MINIMAL RISK',
            'verdict': 'Legitimate',
            'is_phishing': False,
            'color': 'safe'
        }

def predict_url(url: str):
    data = load_trained_model()
    model = data['model']

    features = extract_features(url)
    features_df = pd.DataFrame([[features[f] for f in FEATURE_NAMES]], columns=FEATURE_NAMES)

    prob = model.predict_proba(features_df)[0]
    raw_phishing_prob = prob[1] * 100

    risk_info = calculate_risk_degree(raw_phishing_prob, features)

    print("\n" + "=" * 60)
    print(" URL PHISHING ANALYSIS")
    print("=" * 60)
    print(f"Target URL:       {url}")
    print(f"Verdict:          [{risk_info['verdict'].upper()}]")
    print(f"Risk Degree:      [{risk_info['label']}]")
    print("-" * 60)
    print("Extracted Feature Highlights:")
    print(f" - Brand Spoofing:        {'YES (CRITICAL THREAT)' if features['brand_spoofed'] else 'No'}")
    print(f" - Trusted Authority:     {'YES (Verified Root Domain)' if features['is_trusted_domain'] else 'No'}")
    print(f" - Suspicious TLD:        {'YES (.tk / .xyz / etc.)' if features['suspicious_tld'] else 'Standard TLD'}")
    print(f" - IP Address Host:       {'Yes' if features['having_ip'] else 'No'}")
    print(f" - Shortening Service:    {'Yes' if features['shortening_service'] else 'No'}")
    print(f" - Subdomains Count:      {features['subdomains_count']}")
    print(f" - Hyphen in Domain:      {'Yes' if features['prefix_suffix'] else 'No'}")
    print("=" * 60 + "\n")

    return {
        'url': url,
        'verdict': risk_info['verdict'],
        'risk_level': risk_info['level'],
        'risk_label': risk_info['label'],
        'is_phishing': risk_info['is_phishing'],
        'status_color': risk_info['color'],
        'features': features
    }

if __name__ == "__main__":
    if len(sys.argv) > 1:
        target_url = sys.argv[1]
    else:
        target_url = input("Enter a URL to test: ").strip()

    if target_url:
        predict_url(target_url)
    else:
        print("[-] No URL provided.")
