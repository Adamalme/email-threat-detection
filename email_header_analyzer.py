"""
email_header_analyzer.py (v2)
Flags signs of spoofing, phishing, BEC, and impersonation in saved emails (.eml).

Single email:   python email_header_analyzer.py suspicious.eml
Whole folder:   python email_header_analyzer.py samples
    If the folder has "phishing" and "legit" subfolders, the script also scores
    its own accuracy (true/false positives and negatives, precision, recall).
    Results are saved to results.csv.

How to get a .eml: in Gmail open the email -> three dots -> "Download message".
"""
import csv
import os
import re
import sys
from email import policy
from email.parser import BytesParser
from email.utils import parseaddr
from difflib import SequenceMatcher

# ---- Edit these for the organization you are protecting ----
TRUSTED_DOMAINS = ["microsoft.com", "paypal.com", "amazon.com", "gmail.com"]
VIP_NAMES = ["jane smith", "ceo", "chief executive", "payroll", "it support"]
BEC_KEYWORDS = ["wire transfer", "gift card", "urgent", "invoice", "bank details",
                "payment update", "are you available", "confidential", "direct deposit"]
FLAG_THRESHOLD = 3   # score at or above this counts as "flagged"
VERSION = "v2"

# ---- v2 additions (based on Run 1 findings) ----
# Brand name -> the real domains that brand sends from
BRAND_DOMAINS = {
    "paypal": ["paypal.com"], "microsoft": ["microsoft.com", "office.com", "outlook.com"],
    "amazon": ["amazon.com"], "metamask": ["metamask.io"], "ledger": ["ledger.com"],
    "coinbase": ["coinbase.com"], "binance": ["binance.com"], "stellar": ["stellar.org"],
    "netflix": ["netflix.com"], "apple": ["apple.com"], "dhl": ["dhl.com"],
    "docusign": ["docusign.com", "docusign.net"],
}
FREE_MAIL = ["gmail.com", "outlook.com", "hotmail.com", "yahoo.com", "aol.com",
             "icloud.com", "proton.me", "protonmail.com"]
BUSINESS_WORDS = ["order", "invoice", "confirmation", "receipt", "billing", "support", "account"]
PHISH_KEYWORDS = ["wallet", "seed phrase", "recovery phrase", "staking", "airdrop",
                  "verify your", "unusual activity", "suspended", "new update", "claim your"]


def domain_of(address):
    """Return the domain part of an email address, lowercased."""
    addr = parseaddr(address or "")[1]
    return addr.split("@")[-1].lower().strip(">") if "@" in addr else ""


def auth_results(header_text):
    """Pull spf=, dkim=, dmarc= results out of the Authentication-Results header(s)."""
    results = {}
    for check in ("spf", "dkim", "dmarc"):
        match = re.search(rf"\b{check}=(\w+)", header_text or "", re.IGNORECASE)
        results[check] = match.group(1).lower() if match else "none"
    return results


def lookalike(domain):
    """Return the trusted domain this one imitates (similar but not identical), if any."""
    for trusted in TRUSTED_DOMAINS:
        score = SequenceMatcher(None, domain, trusted).ratio()
        if domain and domain != trusted and score >= 0.8:
            return trusted, round(score, 2)
    return None


def get_text(msg):
    """Get the email body as text; return '' if it can't be read."""
    try:
        body = msg.get_body(preferencelist=("plain", "html"))
        return body.get_content() if body else ""
    except Exception:
        return ""


def analyze(path):
    """Analyze one email and return a dictionary of results."""
    with open(path, "rb") as f:
        msg = BytesParser(policy=policy.default).parse(f)

    display_name, from_addr = parseaddr(str(msg.get("From", "")))
    from_domain = domain_of(from_addr)
    return_domain = domain_of(str(msg.get("Return-Path", "")))
    reply_domain = domain_of(str(msg.get("Reply-To", "")))
    subject = str(msg.get("Subject", ""))
    auth_headers = " ".join(str(h) for h in (msg.get_all("Authentication-Results") or []))
    auth = auth_results(auth_headers)

    findings = []

    # 1. Authentication failures (spoofing)
    if auth["dmarc"] == "fail":
        findings.append(("HIGH", "DMARC failed - the visible From domain was not authenticated"))
    if auth["spf"] in ("fail", "softfail"):
        findings.append(("MEDIUM", f"SPF {auth['spf']} - sending server not authorized by {return_domain}"))
    if auth["dkim"] == "fail":
        findings.append(("MEDIUM", "DKIM failed - signature invalid or message altered"))

    # 2. Envelope vs. header mismatch
    if return_domain and from_domain and return_domain != from_domain:
        findings.append(("LOW", f"Return-Path domain ({return_domain}) differs from From domain ({from_domain})"))

    # 3. Reply-To hijack (classic BEC: replies go to the attacker)
    if reply_domain and reply_domain != from_domain:
        findings.append(("HIGH", f"Reply-To goes to a different domain ({reply_domain}) than From ({from_domain})"))

    # 4. Lookalike domain
    hit = lookalike(from_domain)
    if hit:
        findings.append(("HIGH", f"From domain {from_domain} looks like {hit[0]} (similarity {hit[1]})"))

    # 5. Display-name impersonation
    name = display_name.lower()
    if any(vip in name for vip in VIP_NAMES):
        findings.append(("MEDIUM", f"Display name '{display_name}' matches a VIP/role name - verify the sender"))
    for brand, domains in BRAND_DOMAINS.items():
        if brand in name and not any(from_domain == d or from_domain.endswith("." + d) for d in domains):
            findings.append(("HIGH", f"Display name mentions '{brand}' but mail came from {from_domain}"))
            break

    # v2: long digit strings in the display name or sender address
    local_part = from_addr.split("@")[0] if "@" in from_addr else ""
    if re.search(r"\d{6,}", display_name):
        findings.append(("MEDIUM", f"Display name contains a long number: '{display_name}'"))
    elif re.fullmatch(r"\d{6,}", local_part):
        findings.append(("LOW", f"Sender address is only digits: {from_addr}"))

    # v2: free email provider using business language
    subj = subject.lower()
    if from_domain in FREE_MAIL and any(w in subj or w in name for w in BUSINESS_WORDS):
        findings.append(("HIGH", f"Business-style email ('{subject}') sent from free provider {from_domain}"))

    # v2: missing DKIM signature (weak signal - legit senders usually sign)
    if auth["dkim"] == "none":
        findings.append(("LOW", "No DKIM signature - message was not signed"))

    # 6. BEC / urgency language
    text = (subject + " " + get_text(msg)).lower()
    words = [k for k in BEC_KEYWORDS if k in text]
    if words:
        findings.append(("MEDIUM", f"BEC/urgency language found: {', '.join(words)}"))
    phish = [k for k in PHISH_KEYWORDS if k in text]
    if phish:
        findings.append(("MEDIUM", f"Phishing/crypto lure language found: {', '.join(phish)}"))

    findings.sort(key=lambda x: ["HIGH", "MEDIUM", "LOW"].index(x[0]))
    score = sum({"HIGH": 3, "MEDIUM": 2, "LOW": 1}[lvl] for lvl, _ in findings)
    verdict = "LIKELY MALICIOUS" if score >= 6 else "SUSPICIOUS" if score >= 3 else "LOW RISK"

    return {
        "file": path, "display_name": display_name, "from": from_addr,
        "return_domain": return_domain, "reply_domain": reply_domain, "subject": subject,
        "spf": auth["spf"], "dkim": auth["dkim"], "dmarc": auth["dmarc"],
        "findings": findings, "score": score, "verdict": verdict,
    }


def print_report(r):
    print(f"\nFile:        {r['file']}")
    print(f"From:        {r['display_name']} <{r['from']}>")
    print(f"Return-Path: {r['return_domain'] or '-'}   Reply-To: {r['reply_domain'] or '-'}")
    print(f"Subject:     {r['subject']}")
    print(f"Auth:        SPF={r['spf']}  DKIM={r['dkim']}  DMARC={r['dmarc']}")
    print("-" * 70)
    if not r["findings"]:
        print("No red flags found (that does not guarantee the email is safe).")
    for level, text in r["findings"]:
        print(f"[{level:6}] {text}")
    print(f"\nRisk score: {r['score']}  ->  {r['verdict']}\n")


def batch(folder):
    """Analyze every .eml in a folder (and its subfolders) and save results.csv."""
    print(f"Email header analyzer {VERSION}\n")
    rows = []
    for root, _, files in os.walk(folder):
        label = os.path.basename(root).lower()
        expected = label if label in ("phishing", "legit") else "unknown"
        for name in sorted(files):
            if not name.lower().endswith(".eml"):
                continue
            path = os.path.join(root, name)
            try:
                r = analyze(path)
            except Exception as e:
                print(f"[ERROR] Could not read {name}: {e}")
                continue
            flagged = r["score"] >= FLAG_THRESHOLD
            rows.append({
                "file": name, "expected": expected, "verdict": r["verdict"],
                "score": r["score"], "flagged": "yes" if flagged else "no",
                "spf": r["spf"], "dkim": r["dkim"], "dmarc": r["dmarc"],
                "from": r["from"], "subject": r["subject"],
                "rules_fired": " | ".join(t for _, t in r["findings"]),
            })
            print(f"{r['verdict']:17} score={r['score']:<3} [{expected:8}] {name}")

    if not rows:
        print("No .eml files found in", folder)
        return

    out = os.path.join(folder, "results.csv")
    with open(out, "w", newline="", encoding="utf-8") as f:
        writer = csv.DictWriter(f, fieldnames=rows[0].keys())
        writer.writeheader()
        writer.writerows(rows)
    print(f"\nSaved {len(rows)} results to {out}")

    labeled = [r for r in rows if r["expected"] != "unknown"]
    if labeled:
        tp = sum(r["expected"] == "phishing" and r["flagged"] == "yes" for r in labeled)
        fn = sum(r["expected"] == "phishing" and r["flagged"] == "no" for r in labeled)
        fp = sum(r["expected"] == "legit" and r["flagged"] == "yes" for r in labeled)
        tn = sum(r["expected"] == "legit" and r["flagged"] == "no" for r in labeled)
        precision = tp / (tp + fp) if tp + fp else 0
        recall = tp / (tp + fn) if tp + fn else 0
        print("\n=== Detection accuracy ===")
        print(f"True positives  (phishing caught):   {tp}")
        print(f"False negatives (phishing missed):   {fn}")
        print(f"False positives (legit flagged):     {fp}")
        print(f"True negatives  (legit passed):      {tn}")
        print(f"Precision: {precision:.0%}   (of what it flagged, how much was really phishing)")
        print(f"Recall:    {recall:.0%}   (of all phishing, how much it caught)")


if __name__ == "__main__":
    if len(sys.argv) != 2:
        print("Usage: python email_header_analyzer.py <file.eml or folder>")
        sys.exit(1)
    target = sys.argv[1]
    if os.path.isdir(target):
        batch(target)
    else:
        print_report(analyze(target))
