"""
Dataset Generation Script using Benchmark 10K Domains and OpenPhish Live Feed.
Combines real-world phishing and legitimate URLs for robust, unbiased model training.
"""

import os
import csv
import urllib.request
import pandas as pd
from feature_extraction import extract_features, FEATURE_NAMES

DATASET_DIR = os.path.join(os.path.dirname(__file__), "dataset")
OUTPUT_PATH = os.path.join(DATASET_DIR, "phishing_urls.csv")
BENCHMARK_URL = "https://raw.githubusercontent.com/shreyagopal/Phishing-Website-Detection-by-Machine-Learning-Techniques/master/DataFiles/5.urldata.csv"

# Diverse realistic legitimate URL patterns
BASE_LEGITIMATE_URLS = [
    "https://www.google.com",
    "https://www.google.com/search?q=cybersecurity+defense",
    "https://accounts.google.com/signin/v2/identifier",
    "https://mail.google.com/mail/u/0/#inbox",
    "https://support.google.com/accounts/answer/41078",
    "https://drive.google.com/drive/u/0/my-drive",
    "https://docs.google.com/document/u/0/",
    "https://github.com",
    "https://github.com/login",
    "https://github.com/torvalds/linux",
    "https://github.com/features/security",
    "https://gist.github.com/discover",
    "https://www.microsoft.com",
    "https://login.microsoftonline.com/common/oauth2/authorize",
    "https://azure.microsoft.com/en-us/solutions",
    "https://support.microsoft.com/en-us/windows",
    "https://www.amazon.com",
    "https://www.amazon.com/ap/signin",
    "https://aws.amazon.com/console/",
    "https://aws.amazon.com/iam/",
    "https://www.paypal.com",
    "https://www.paypal.com/signin",
    "https://www.paypal.com/myaccount/summary",
    "https://www.apple.com",
    "https://appleid.apple.com/sign-in",
    "https://support.apple.com/en-us/HT204915",
    "https://www.wikipedia.org",
    "https://en.wikipedia.org/wiki/Phishing",
    "https://en.wikipedia.org/wiki/Machine_learning",
    "https://www.linkedin.com",
    "https://www.linkedin.com/login",
    "https://www.linkedin.com/jobs/search",
    "https://www.youtube.com",
    "https://www.youtube.com/watch?v=kJQP7kiw5Fk",
    "https://www.reddit.com",
    "https://www.reddit.com/r/netsec/",
    "https://stackoverflow.com",
    "https://stackoverflow.com/users/login",
    "https://pypi.org/project/scikit-learn/",
    "https://docs.python.org/3/library/urllib.parse.html",
    "https://www.netflix.com/login",
    "https://www.chase.com",
    "https://secure.chase.com/web/auth/dashboard",
    "https://www.bankofamerica.com",
    "https://www.wellsfargo.com",
    "https://www.facebook.com/login.php",
    "https://www.instagram.com/accounts/login/",
    "https://x.com/i/flow/login",
    "https://www.cloudflare.com/learning/access-management/phishing-attack/",
    "https://news.ycombinator.com/login",
    "https://medium.com/tag/machine-learning",
    "https://dev.to/t/security",
    "https://hub.docker.com/_/python",
    "https://gitlab.com/users/sign_in",
    "https://wordpress.org/download/",
    "https://weather.com/weather/today",
    "https://www.bbc.com/news",
    "https://www.nytimes.com",
    "https://www.cnn.com",
    "https://www.imdb.com/chart/top/",
    "https://www.spotify.com/us/signup",
    "https://open.spotify.com/search",
    "https://zoom.us/signin",
    "https://slack.com/signin",
    "https://discord.com/login",
    "https://www.twitch.tv/directory",
    "https://www.coursera.org/learn/cyber-security",
    "https://www.khanacademy.org",
    "https://www.kaggle.com/datasets",
    "https://huggingface.co/models"
]

def fetch_openphish_urls():
    """Fetches real-time verified phishing URLs from OpenPhish feed."""
    print("[*] Fetching live verified phishing links from OpenPhish...")
    try:
        req = urllib.request.Request(
            'https://openphish.com/feed.txt',
            headers={'User-Agent': 'Mozilla/5.0'}
        )
        with urllib.request.urlopen(req, timeout=10) as response:
            lines = response.read().decode('utf-8', errors='ignore').splitlines()
            valid_urls = [line.strip() for line in lines if line.strip().startswith('http')]
            print(f"[+] Retrieved {len(valid_urls)} live phishing URLs from OpenPhish.")
            return valid_urls
    except Exception as e:
        print(f"[!] Warning: Could not fetch OpenPhish feed ({e}). Proceeding with benchmark data.")
        return []

def load_benchmark_dataset():
    """Loads and samples from the established 10,000 domains dataset."""
    print("[*] Fetching benchmark 10,000 URL dataset (UNB / PhishTank)...")
    try:
        df = pd.read_csv(BENCHMARK_URL)
        print(f"[+] Successfully loaded {len(df)} samples from benchmark dataset.")
        return df
    except Exception as e:
        print(f"[!] Warning: Could not fetch remote benchmark ({e}).")
        return None

def build_dataset():
    os.makedirs(DATASET_DIR, exist_ok=True)
    records = []

    # 1. Add base verified legitimate URLs
    for url in BASE_LEGITIMATE_URLS:
        features = extract_features(url)
        features['url'] = url
        features['label'] = 0
        records.append(features)

    # 2. Add OpenPhish live phishing URLs
    openphish_urls = fetch_openphish_urls()
    for url in openphish_urls:
        features = extract_features(url)
        features['url'] = url
        features['label'] = 1
        records.append(features)

    # 3. Add benchmark 10k dataset domains
    benchmark_df = load_benchmark_dataset()
    if benchmark_df is not None:
        # Sample 2,500 legitimate and 2,500 phishing for balanced high-speed training
        legit_sample = benchmark_df[benchmark_df['Label'] == 0].sample(n=min(2500, sum(benchmark_df['Label'] == 0)), random_state=42)
        phish_sample = benchmark_df[benchmark_df['Label'] == 1].sample(n=min(2500, sum(benchmark_df['Label'] == 1)), random_state=42)

        for _, row in legit_sample.iterrows():
            domain = str(row['Domain'])
            url = f"https://www.{domain}"
            features = extract_features(url)
            features['url'] = url
            features['label'] = 0
            records.append(features)

        for _, row in phish_sample.iterrows():
            domain = str(row['Domain'])
            # Modern phishing frequently uses HTTPS as well as HTTP
            scheme = "https://" if hash(domain) % 2 == 0 else "http://"
            url = f"{scheme}{domain}"
            features = extract_features(url)
            features['url'] = url
            features['label'] = 1
            records.append(features)

    # 4. Save final combined CSV
    fieldnames = ['url'] + FEATURE_NAMES + ['label']
    with open(OUTPUT_PATH, mode='w', newline='', encoding='utf-8') as f:
        writer = csv.DictWriter(f, fieldnames=fieldnames)
        writer.writeheader()
        for r in records:
            writer.writerow(r)

    phish_count = sum(r['label'] == 1 for r in records)
    legit_count = sum(r['label'] == 0 for r in records)
    print(f"\n[+] Total Dataset generated: {len(records)} samples ({phish_count} Phishing, {legit_count} Legitimate)")
    print(f"[+] Output saved to: {OUTPUT_PATH}")

if __name__ == "__main__":
    build_dataset()
