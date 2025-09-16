#!/usr/bin/env python3
"""
Phishing Link Scanner (Heuristic)
Author: Raymond Favour Joshua
Description:
  - Scores URLs based on common phishing indicators (no external APIs required).
  - Works in two modes:
      1) Single URL via --url
      2) Batch mode via --input_csv and optional --output_csv
  - Optional live checks (HEAD/GET) if --live flag is used (may be blocked by your network).
"""

import argparse
import math
import re
import sys
import json
import csv
from urllib.parse import urlparse
from collections import Counter

try:
    import tldextract
except ImportError:
    print("Missing dependency: tldextract. Install with: pip install tldextract", file=sys.stderr)
    raise

try:
    import pandas as pd
except Exception:
    pd = None

try:
    import requests
except Exception:
    requests = None

SUSPICIOUS_TLDS = {
    "zip","mov","work","top","xyz","gq","cf","tk","ml","cam","rest","country","tokyo","click","fit","link"
}

URL_SHORTENERS = {
    "bit.ly","tinyurl.com","t.co","goo.gl","ow.ly","is.gd","buff.ly","adf.ly","cutt.ly","rb.gy","rebrand.ly","tiny.cc"
}

SENSITIVE_KEYWORDS = {
    "login","signin","verify","update","secure","account","bank","wallet","password","reset","confirm","billing",
    "invoice","payment","office365","microsoft","paypal","apple","meta","facebook","instagram","whatsapp","telegram"
}

BRAND_SPOOF_WORDS = {
    "rnicrosoft","paypa1","faceb00k","microsof7","app1e","go0gle","0ffice","0utlook","0fficial"
}

SUSPICIOUS_PATH_PATTERNS = [
    re.compile(r"/\d{6,}"),
    re.compile(r"/[a-z]{10,}\d+"),
    re.compile(r"(?:base64|data:)"),
]

IP_HOST_RE = re.compile(r"^(?:\d{1,3}\.){3}\d{1,3}$")

def shannon_entropy(s: str) -> float:
    """
    Compute Shannon entropy of a string (approx measure of randomness).
    Higher values suggest random-looking hostnames (e.g., DGA-generated).
    """
    if not s:
        return 0.0
    counts = Counter(s)
    n = len(s)
    return -sum((c/n) * math.log2(c/n) for c in counts.values())

def features_from_url(url: str) -> dict:
    """
    Extract a set of features/flags from a URL used for scoring.
    Returns a dictionary of features (both numeric and flags).
    """
    fe = {}
    parsed = urlparse(url if "://" in url else "http://" + url)
    host = parsed.hostname or ""
    path_q = (parsed.path or "") + ("?" + parsed.query if parsed.query else "")
    ext = tldextract.extract(url)
    registered_domain = ".".join([p for p in [ext.domain, ext.suffix] if p])

    fe["scheme"] = parsed.scheme or "http"
    fe["uses_https"] = 1 if parsed.scheme.lower() == "https" else 0
    fe["has_at_symbol"] = 1 if "@" in url else 0
    fe["url_length"] = len(url)
    fe["host_length"] = len(host)
    fe["path_length"] = len(parsed.path or "")
    fe["num_dots"] = url.count(".")
    fe["num_hyphens"] = url.count("-")
    fe["num_digits"] = sum(ch.isdigit() for ch in url)
    fe["has_ip_host"] = 1 if IP_HOST_RE.match(host or "") else 0
    fe["is_url_shortener"] = 1 if registered_domain in URL_SHORTENERS else 0
    fe["tld_in_suspicious_list"] = 1 if ext.suffix.split(".")[-1] in SUSPICIOUS_TLDS else 0
    fe["contains_punycode"] = 1 if "xn--" in host else 0
    fe["subdomain_count"] = max(0, len([p for p in host.split(".") if p]) - 2)

    lower_combo = (host + path_q).lower()
    fe["has_sensitive_keyword"] = 1 if any(k in lower_combo for k in SENSITIVE_KEYWORDS) else 0
    fe["has_brand_spoof_word"] = 1 if any(k in lower_combo for k in BRAND_SPOOF_WORDS) else 0
    fe["path_has_suspicious_pattern"] = 1 if any(p.search(path_q.lower()) for p in SUSPICIOUS_PATH_PATTERNS) else 0
    fe["host_entropy"] = round(shannon_entropy(host), 3)

    fe["registered_domain"] = registered_domain
    fe["host"] = host
    fe["path_q"] = path_q
    fe["raw_url"] = url
    return fe

def score_url(fe: dict) -> dict:
    """
    Rule-based scoring. Returns a dictionary containing:
      - score: 0..100 numeric
      - label: Likely OK / Suspicious / High-Risk
      - reasons: list of human-readable reasons for points added
    """
    score = 0
    reasons = []

    def add(points, reason):
        nonlocal score
        score += points
        reasons.append(f"+{points}: {reason}")

    if fe["uses_https"] == 0:
        add(10, "URL does not use HTTPS")
    if fe["has_at_symbol"]:
        add(10, "Contains '@' symbol (possible redirection)")
    if fe["has_ip_host"]:
        add(15, "Uses raw IP as host")
    if fe["tld_in_suspicious_list"]:
        add(10, "Suspicious/abused TLD")
    if fe["is_url_shortener"]:
        add(10, "Known URL shortener (conceals destination)")
    if fe["contains_punycode"]:
        add(10, "Punycode in hostname")
    if fe["subdomain_count"] >= 3:
        add(10, "Excessive subdomains")
    if fe["num_hyphens"] >= 4:
        add(5, "Many hyphens in URL")
    if fe["num_digits"] >= 10:
        add(5, "Many digits in URL")
    if fe["url_length"] >= 90:
        add(5, "Very long URL")
    if fe["has_sensitive_keyword"]:
        add(10, "Contains sensitive keywords")
    if fe["has_brand_spoof_word"]:
        add(15, "Contains brand-spoofing patterns")
    if fe["path_has_suspicious_pattern"]:
        add(5, "Suspicious path pattern")
    if fe["host_entropy"] >= 3.6:
        add(10, "High host entropy (random-looking)")

    score = min(100, score)

    if score >= 40:
        label = "High-Risk"
    elif score >= 20:
        label = "Suspicious"
    else:
        label = "Likely OK"

    return {
        "score": score,
        "label": label,
        "reasons": reasons,
    }

def live_checks(url: str, timeout=6):
    """
    Optional lightweight live checks using HTTP requests.
    - Follows redirects to reveal final landing URL
    - Returns status code, final_url, redirect_count, and optional page title
    If requests is not installed or network blocked, returns a dict with live_error.
    """
    if requests is None:
        return {"live_error": "requests not installed"}

    info = {}
    try:
        resp = requests.head(url, allow_redirects=True, timeout=timeout)
        info["status_code"] = resp.status_code
        info["final_url"] = resp.url
        info["redirect_count"] = len(resp.history)
        if resp.status_code >= 400 or "text/html" in resp.headers.get("Content-Type",""):
            r2 = requests.get(url, allow_redirects=True, timeout=timeout)
            info["final_url"] = r2.url
            info["status_code"] = r2.status_code
            m = re.search(r"<title>(.*?)</title>", r2.text, flags=re.IGNORECASE|re.DOTALL)
            if m:
                info["page_title"] = m.group(1).strip()[:150]
    except Exception as e:
        info["live_error"] = str(e)
    return info

def scan_url(url: str, do_live=False) -> dict:
    """
    High-level function scanning a single URL.
    - Extract features
    - Score URL
    - Optionally run live checks and merge their outputs
    Returns a flattened record (dictionary)
    """
    fe = features_from_url(url)
    scored = score_url(fe)
    record = {**fe, **scored}
    if do_live:
        record.update({f"live_{k}": v for k, v in live_checks(url).items()})
    return record

def main():
    """
    CLI entrypoint. Supports:
     - --url <single url>
     - --input_csv <csvpath> --output_csv <csvpath>
     - --json (print single result as JSON)
     - --live (perform HTTP live checks)
    """
    ap = argparse.ArgumentParser(description="Phishing Link Scanner (Heuristic)")
    ap.add_argument("--url", help="Single URL to scan")
    ap.add_argument("--input_csv", help="CSV with a column named 'url' for batch scanning")
    ap.add_argument("--output_csv", help="Where to write the batch report CSV")
    ap.add_argument("--json", action="store_true", help="Print result as JSON to stdout (single URL mode)")
    ap.add_argument("--live", action="store_true", help="Perform optional live checks (network)")
    args = ap.parse_args()

    if args.url:
        rec = scan_url(args.url, do_live=args.live)
        if args.json:
            print(json.dumps(rec, indent=2))
        else:
            print(f"[{rec['label']}] score={rec['score']} url={rec['raw_url']}")
            for r in rec["reasons"]:
                print("  -", r)
        return 0

    if args.input_csv:
        if pd is None:
            print("pandas not available. Install with: pip install pandas", file=sys.stderr)
            return 2
        df = pd.read_csv(args.input_csv)
        if "url" not in df.columns:
            print("Input CSV must have a 'url' column", file=sys.stderr)
            return 2
        rows = []
        for u in df["url"].astype(str):
            rows.append(scan_url(u, do_live=args.live))
        out = pd.DataFrame(rows)
        if args.output_csv:
            out.to_csv(args.output_csv, index=False)
            print(f"Wrote report: {args.output_csv}")
        else:
            print(out.head().to_string(index=False))
        return 0

    ap.print_help()
    return 0

if __name__ == "__main__":
    sys.exit(main())

import argparse
import sys
import pandas as pd
from urllib.parse import urlparse

def features_from_url(url: str) -> dict:
    parsed = urlparse(url)
    return {
        "url": url,
        "domain": parsed.netloc,
        "path": parsed.path,
        "has_https": url.startswith("https"),
        "suspicious_chars": any(c in url for c in ["@", "-", "_", "=", "%"]),
        "url_length": len(url)
    }

def score_url(features: dict) -> str:
    score = 0

    if not features["has_https"]:
        score += 1
    if features["suspicious_chars"]:
        score += 1
    if features["url_length"] > 75:
        score += 1

    if score >= 2:
        return "Phishing (High Risk)"
    elif score == 1:
        return "Suspicious"
    else:
        return "Safe"

def analyze_url(url: str) -> dict:
    features = features_from_url(url)
    label = score_url(features)
    features["label"] = label
    return features

def main():
    parser = argparse.ArgumentParser(description="Phishing Link Scanner")
    parser.add_argument("--url", help="Scan a single URL")
    parser.add_argument("--input_csv", help="CSV file with a column 'url'")
    parser.add_argument("--output_csv", help="Save results to CSV file")
    args = parser.parse_args()

    results = []

    if args.url:
        result = analyze_url(args.url)
        print(result)
        results.append(result)

    if args.input_csv:
        df = pd.read_csv(args.input_csv)
        for u in df["url"]:
            results.append(analyze_url(u))
        if args.output_csv:
            pd.DataFrame(results).to_csv(args.output_csv, index=False)
            print(f"Results saved to {args.output_csv}")

    return 0

if __name__ == "__main__":
    sys.exit(main())
