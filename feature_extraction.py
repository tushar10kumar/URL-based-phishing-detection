"""
Advanced URL Feature Extraction Module for Phishing Detection.
Accurately analyzes lexical patterns, domain hierarchy, brand spoofing,
suspicious TLDs, and path structure without HTTPS bias.
"""

import re
import math
from urllib.parse import urlparse

# High-profile targets often impersonated by phishing attacks
KNOWN_BRANDS = {
    'google': 'google.com',
    'paypal': 'paypal.com',
    'apple': 'apple.com',
    'microsoft': 'microsoft.com',
    'amazon': 'amazon.com',
    'netflix': 'netflix.com',
    'chase': 'chase.com',
    'bankofamerica': 'bankofamerica.com',
    'wellsfargo': 'wellsfargo.com',
    'facebook': 'facebook.com',
    'instagram': 'instagram.com',
    'whatsapp': 'whatsapp.com',
    'twitter': 'twitter.com',
    'x': 'x.com',
    'binance': 'binance.com',
    'coinbase': 'coinbase.com',
    'metamask': 'metamask.io',
    'dropbox': 'dropbox.com',
    'steam': 'steampowered.com',
    'roblox': 'roblox.com',
    'linkedin': 'linkedin.com',
    'adobe': 'adobe.com',
    'yahoo': 'yahoo.com',
    'outlook': 'outlook.com',
    'office365': 'office.com',
    'ebay': 'ebay.com'
}

# Major trusted root domains
TRUSTED_DOMAINS = {
    'google.com', 'youtube.com', 'github.com', 'microsoft.com', 'apple.com',
    'amazon.com', 'wikipedia.org', 'linkedin.com', 'reddit.com', 'netflix.com',
    'twitter.com', 'x.com', 'facebook.com', 'instagram.com', 'whatsapp.com',
    'stackoverflow.com', 'python.org', 'pypi.org', 'cloudflare.com', 'medium.com',
    'yahoo.com', 'bing.com', 'ebay.com', 'dropbox.com', 'adobe.com',
    'paypal.com', 'chase.com', 'bankofamerica.com', 'wellsfargo.com',
    'quora.com', 'spotify.com', 'zoom.us', 'slack.com', 'discord.com',
    'twitch.tv', 'gitlab.com', 'kaggle.com', 'huggingface.co', 'mozilla.org'
}

# High-abuse or free TLDs heavily correlated with phishing campaigns
SUSPICIOUS_TLDS = {
    'tk', 'ml', 'ga', 'cf', 'gq', 'xyz', 'top', 'click', 'buzz', 'club',
    'work', 'icu', 'fit', 'rest', 'country', 'stream', 'zip', 'mov', 'kim',
    'link', 'online', 'site', 'vip', 'space', 'pw', 'top', 'fun', 'cc',
    'live', 'support', 'help', 'account', 'security', 'center', 'info'
}

# Known URL shorteners
SHORTENING_SERVICES = {
    'bit.ly', 'tinyurl.com', 'goo.gl', 'ow.ly', 't.co', 'is.gd',
    'cli.gs', 'yfrog.com', 'migre.me', 'ff.im', 'tiny.cc', 'url4.eu',
    'twit.ac', 'su.pr', 'twurl.nl', 'snipurl.com', 'short.to', 'budurl.com',
    'ping.fm', 'post.ly', 'just.as', 'bkite.com', 'snipr.com', 'fic.kr',
    'loopt.us', 'doiop.com', 'short.ie', 'kl.am', 'wp.me', 'rubyurl.com',
    'om.ly', 'to.ly', 'bit.do', 'lnkd.in', 'db.tt', 'qr.ae',
    'adf.ly', 'cur.lv', 'tinyarrows.com', 'ity.im', 'q.gs', 'po.st',
    'bc.vc', 'twitthis.com', 'u.to', 'j.mp', 'buzurl.com', 'cutt.us',
    'u.bb', 'yourls.org', 'x.co', 'cutt.ly', 'rb.gy'
}

SUSPICIOUS_KEYWORDS = [
    'login', 'verify', 'update', 'banking', 'secure', 'account', 'signin',
    'password', 'confirm', 'security', 'service', 'wallet', 'validation',
    'authenticate', 'credential', 'suspend', 'recover', 'billing',
    'webscr', 'alert', 'identity', 'unlock'
]

def calculate_entropy(text: str) -> float:
    """Calculates Shannon entropy of a string."""
    if not text:
        return 0.0
    freq = {}
    for char in text:
        freq[char] = freq.get(char, 0) + 1
    entropy = 0.0
    length = len(text)
    for count in freq.values():
        p = count / length
        entropy -= p * math.log2(p)
    return round(entropy, 4)

def get_root_domain(domain: str) -> str:
    """Extracts base registered domain (e.g., 'sub.example.com' -> 'example.com')."""
    domain = domain.lower().split(':')[0]
    parts = domain.split('.')
    if len(parts) >= 2:
        # Check two-part ccTLDs like .co.uk, .com.au
        if len(parts) >= 3 and parts[-2] in ('co', 'com', 'org', 'net', 'edu', 'gov'):
            return '.'.join(parts[-3:])
        return '.'.join(parts[-2:])
    return domain

def extract_features(url: str) -> dict:
    """
    Extracts comprehensive lexical and contextual features from a given URL.
    Returns a dictionary of numerical feature values.
    """
    url_clean = url.strip()
    url_lower = url_clean.lower()
    if not (url_lower.startswith('http://') or url_lower.startswith('https://')):
        url_lower = 'http://' + url_lower

    parsed = urlparse(url_lower)
    full_host = parsed.netloc.split(':')[0]
    root_domain = get_root_domain(full_host)
    path = parsed.path
    query = parsed.query
    tld = full_host.split('.')[-1] if '.' in full_host else ''

    # 1. Direct IP Address detection
    ipv4_pattern = r'^((25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\.){3}(25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)$'
    having_ip = 1 if re.match(ipv4_pattern, full_host) else 0

    # 2. URL Shortener detection
    shortening_service = 1 if any(short in full_host for short in SHORTENING_SERVICES) else 0

    # 3. '@' Symbol in URL
    having_at = 1 if '@' in url_lower else 0

    # 4. Double slash redirect in path
    double_slash = 1 if '//' in path else 0

    # 5. Prefix/Suffix '-' in domain name (e.g., paypal-secure.com)
    prefix_suffix = 1 if '-' in full_host else 0

    # 6. Subdomain Depth (subdomain count excluding www and root)
    clean_host = full_host.replace('www.', '')
    dots_count = clean_host.count('.')
    subdomains_count = max(0, dots_count - 1)
    has_excessive_subdomains = 1 if subdomains_count >= 2 else 0

    # 7. Brand Impersonation / Spoofing
    # Brand appears in hostname, but the root domain is NOT the official brand domain!
    brand_spoofed = 0
    for brand, official_domain in KNOWN_BRANDS.items():
        if brand in full_host and root_domain != official_domain:
            brand_spoofed = 1
            break

    # 8. Suspicious / Abused TLD
    suspicious_tld = 1 if tld in SUSPICIOUS_TLDS else 0

    # 9. Credential Harvesting Keywords in Domain vs Path
    keywords_in_domain = sum(1 for kw in SUSPICIOUS_KEYWORDS if kw in full_host)
    has_keywords_in_domain = 1 if keywords_in_domain > 0 else 0

    keywords_in_path = sum(1 for kw in SUSPICIOUS_KEYWORDS if kw in path or kw in query)

    # 10. URL Length metrics
    url_length = len(url_lower)
    is_long_url = 1 if url_length >= 75 else 0
    domain_length = len(full_host)

    # 11. Digits count & ratio
    num_digits = sum(c.isdigit() for c in url_lower)
    digit_ratio = round(num_digits / max(url_length, 1), 4)

    # 12. Special characters count
    num_special_chars = sum(url_lower.count(c) for c in ['?', '=', '&', '%', '_', '-', '+', '~'])

    # 13. URL Entropy
    url_entropy = calculate_entropy(url_lower)

    # 14. Trusted Authority Domain Flag
    is_trusted_domain = 1 if root_domain in TRUSTED_DOMAINS else 0

    # 15. HTTPS used in domain part to deceive (e.g. https-paypal.com)
    https_in_domain = 1 if ('https' in full_host or 'http' in full_host) and not full_host.startswith('http') else 0

    return {
        'having_ip': having_ip,
        'shortening_service': shortening_service,
        'having_at': having_at,
        'double_slash': double_slash,
        'prefix_suffix': prefix_suffix,
        'subdomains_count': subdomains_count,
        'has_excessive_subdomains': has_excessive_subdomains,
        'brand_spoofed': brand_spoofed,
        'suspicious_tld': suspicious_tld,
        'has_keywords_in_domain': has_keywords_in_domain,
        'keywords_in_path': keywords_in_path,
        'is_long_url': is_long_url,
        'domain_length': domain_length,
        'digit_ratio': digit_ratio,
        'num_special_chars': num_special_chars,
        'url_entropy': url_entropy,
        'is_trusted_domain': is_trusted_domain,
        'https_in_domain': https_in_domain
    }

FEATURE_NAMES = [
    'having_ip',
    'shortening_service',
    'having_at',
    'double_slash',
    'prefix_suffix',
    'subdomains_count',
    'has_excessive_subdomains',
    'brand_spoofed',
    'suspicious_tld',
    'has_keywords_in_domain',
    'keywords_in_path',
    'is_long_url',
    'domain_length',
    'digit_ratio',
    'num_special_chars',
    'url_entropy',
    'is_trusted_domain',
    'https_in_domain'
]
