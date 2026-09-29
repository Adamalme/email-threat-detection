# Email Threat Detection: Phishing, BEC & Spoofing Analysis

<img width="1536" height="1024" alt="image" src="https://github.com/user-attachments/assets/d46b88e3-cced-481f-9ada-fb1fdd801fcb" />


A Python detector that analyzes raw email headers (`.eml` files) for signs of spoofing, phishing, business email compromise (BEC), and brand impersonation, and **measures its own accuracy** against labeled samples. It includes a KQL version of the same detection for Microsoft Defender Advanced Hunting.

The project follows a detection engineering loop: **build → measure → study the failures → improve → re-measure on unseen data.**

## Results

| | v1 | v2 (training set) | v2 (held-out test set) |
|---|---|---|---|
| **Recall** (phishing caught) | 56% | 94% | **87%** |
| **Precision** (flags that were real phishing) | not measured | not measured | **93%** |
| False positives | — | — | 1 of 7 real emails |

- The **held-out test set** (15 real phishing emails + 7 real legitimate emails) was never used to build or tune the rules, so its numbers are the honest measure of performance.
- The small gap between training (94%) and test (87%) recall shows the rules learned general patterns rather than memorizing specific emails.

Full analysis of every miss and false positive: [`findings.md`](findings.md)

## How it works

Each email is scored by a set of weighted rules. A total score of 3 or more counts as flagged.

| Rule | Weight | Catches |
|---|---|---|
| DMARC failure | HIGH (3) | Spoofed sender domains |
| Reply-To points to a different domain than From | HIGH (3) | BEC reply hijacking |
| Lookalike domain (e.g., `paypa1.com`) | HIGH (3) | Typosquatting |
| Brand in display name, but sender is not that brand's real domain | HIGH (3) | Brand impersonation (PayPal, Microsoft, MetaMask, Ledger, Coinbase, ...) |
| Business-style subject from a free email provider | HIGH (3) | Fake order confirmations and invoices from Gmail/Outlook |
| SPF fail / softfail | MEDIUM (2) | Unauthorized sending servers |
| DKIM failure | MEDIUM (2) | Altered or forged messages |
| Display name is a VIP or role name | MEDIUM (2) | Executive impersonation |
| Long number in display name | MEDIUM (2) | Auto-generated scam sender names |
| BEC / urgency language | MEDIUM (2) | "wire transfer", "gift card", "bank details" |
| Phishing / crypto lure language | MEDIUM (2) | "wallet", "seed phrase", "staking", "verify your" |
| Return-Path differs from From | LOW (1) | Weak envelope mismatch signal |
| Sender address is only digits | LOW (1) | Throwaway accounts |
| No DKIM signature | LOW (1) | Unsigned mail (weak signal) |

## Key findings

1. **Crypto brand impersonation was the biggest gap in v1.** Four of seven misses impersonated MetaMask, Ledger, or Stellar. Expanding the brand list with each brand's real domains fixed them.
2. **Authentication is not enough.** Compromised legitimate accounts pass SPF, DKIM, and DMARC because the mail really comes from that domain. These remain the hardest cases for header-based detection.
3. **Reputation lag is real.** The sender domain, Reply-To domain, and landing page of a confirmed casino scam all scored **0/92 on VirusTotal**. "No detections" means "not known to be bad," not "safe."
4. **The one false positive revealed a logic flaw.** A Handshake notification was flagged because Reply-To (`joinhandshake.com`) differed from From (`notifications.joinhandshake.com`). Both belong to the same organization; the rule compared full domains instead of registered domains. The fix is planned for v3 and was not applied to v2, to keep the test results honest.
5. **Clean baseline in Microsoft Defender.** In a lab tenant, all 52 inbound emails over 30 days passed SPF/DKIM/DMARC, and the KQL detection correctly returned zero alerts on clean traffic.

## KQL version (Microsoft Defender for Office 365)

The same scoring logic, written in KQL for Microsoft Defender Advanced Hunting.

### Self-contained test (anyone can run this)

This version includes two built-in sample emails, so it runs in any Advanced Hunting console with no data setup. A spoofed PayPal email scores 14 (flagged); a legitimate GitHub email scores 0 (ignored).

```kql
let TestEmails = datatable(Timestamp:datetime, EmailDirection:string, AuthenticationDetails:string,
    SenderFromDomain:string, SenderMailFromDomain:string, SenderDisplayName:string,
    SenderFromAddress:string, RecipientEmailAddress:string, Subject:string, DeliveryAction:string)
[
    datetime(2026-09-28), "Inbound", '{"SPF":"softfail","DKIM":"none","DMARC":"fail"}',
        "paypa1.com", "mailer-xyz.ru", "PayPal Security", "service@paypa1.com",
        "user@lab.local", "URGENT: Payment update required", "Delivered",
    datetime(2026-09-28), "Inbound", '{"SPF":"pass","DKIM":"pass","DMARC":"pass"}',
        "github.com", "github.com", "GitHub", "noreply@github.com",
        "user@lab.local", "Your weekly digest", "Delivered"
];
let TrustedDomains = dynamic(["microsoft.com", "paypal.com", "amazon.com"]);
let Brands = dynamic(["PayPal", "Microsoft", "Amazon"]);
let VIPNames = dynamic(["CEO", "Chief Executive", "Payroll", "IT Support"]);
let BECWords = dynamic(["wire transfer", "gift card", "urgent", "invoice",
                        "bank details", "payment update", "direct deposit"]);
TestEmails
| where Timestamp > ago(30d)
| where EmailDirection == "Inbound"
| extend Auth = parse_json(AuthenticationDetails)
| extend SPF = tostring(Auth.SPF), DKIM = tostring(Auth.DKIM), DMARC = tostring(Auth.DMARC)
| extend Normalized = replace_string(replace_string(replace_string(
                          tolower(SenderFromDomain), "1", "l"), "0", "o"), "rn", "m")
| extend
    R_DMARC     = iff(DMARC == "fail", 3, 0),
    R_SPF       = iff(SPF in ("fail", "softfail"), 2, 0),
    R_DKIM      = iff(DKIM == "fail", 2, 0),
    R_Mismatch  = iff(isnotempty(SenderMailFromDomain) and SenderMailFromDomain != SenderFromDomain, 1, 0),
    R_Lookalike = iff(Normalized in (TrustedDomains) and SenderFromDomain !in (TrustedDomains), 3, 0),
    R_Brand     = iff(SenderDisplayName has_any (Brands) and SenderFromDomain !in (TrustedDomains), 3, 0),
    R_VIP       = iff(SenderDisplayName has_any (VIPNames), 2, 0),
    R_BEC       = iff(Subject has_any (BECWords), 2, 0)
| extend RiskScore = R_DMARC + R_SPF + R_DKIM + R_Mismatch + R_Lookalike + R_Brand + R_VIP + R_BEC
| where RiskScore >= 3
| project Timestamp, RiskScore, SenderDisplayName, SenderFromAddress, SenderMailFromDomain,
          RecipientEmailAddress, Subject, SPF, DKIM, DMARC, DeliveryAction
| order by RiskScore desc
```

Validated in Microsoft Defender Advanced Hunting: the spoofed PayPal email scored **14** and was flagged; the GitHub email scored 0 and was ignored. Run against real lab traffic, the same detection returned **0 alerts on 52 clean inbound emails** (no false positives).

### Production version

For real data, replace the `TestEmails` block with the `EmailEvents` table:

```kql
let TrustedDomains = dynamic(["microsoft.com", "paypal.com", "amazon.com"]);
let Brands = dynamic(["PayPal", "Microsoft", "Amazon"]);
let VIPNames = dynamic(["CEO", "Chief Executive", "Payroll", "IT Support"]);
let BECWords = dynamic(["wire transfer", "gift card", "urgent", "invoice",
                        "bank details", "payment update", "direct deposit"]);
EmailEvents
| where Timestamp > ago(30d)
| where EmailDirection == "Inbound"
| extend Auth = parse_json(AuthenticationDetails)
| extend SPF = tostring(Auth.SPF), DKIM = tostring(Auth.DKIM), DMARC = tostring(Auth.DMARC)
| extend Normalized = replace_string(replace_string(replace_string(
                          tolower(SenderFromDomain), "1", "l"), "0", "o"), "rn", "m")
| extend
    R_DMARC     = iff(DMARC == "fail", 3, 0),
    R_SPF       = iff(SPF in ("fail", "softfail"), 2, 0),
    R_DKIM      = iff(DKIM == "fail", 2, 0),
    R_Mismatch  = iff(isnotempty(SenderMailFromDomain) and SenderMailFromDomain != SenderFromDomain, 1, 0),
    R_Lookalike = iff(Normalized in (TrustedDomains) and SenderFromDomain !in (TrustedDomains), 3, 0),
    R_Brand     = iff(SenderDisplayName has_any (Brands) and SenderFromDomain !in (TrustedDomains), 3, 0),
    R_VIP       = iff(SenderDisplayName has_any (VIPNames), 2, 0),
    R_BEC       = iff(Subject has_any (BECWords), 2, 0)
| extend RiskScore = R_DMARC + R_SPF + R_DKIM + R_Mismatch + R_Lookalike + R_Brand + R_VIP + R_BEC
| where RiskScore >= 3
| project Timestamp, RiskScore, SenderDisplayName, SenderFromAddress, SenderMailFromDomain,
          RecipientEmailAddress, Subject, SPF, DKIM, DMARC, DeliveryAction
| order by RiskScore desc
```

`EmailEvents` does not include the Reply-To header, so that rule is Python-only.

## How to run

Requires Python 3 (standard library only).

```bash
# Analyze one email
python email_header_analyzer.py suspicious.eml

# Analyze a folder and measure accuracy
# (subfolders named "phishing" and "legit" are treated as labels)
python email_header_analyzer.py samples
```

Batch mode prints a verdict per email, saves `results.csv`, and reports true/false positives and negatives, precision, and recall.

### Getting phishing samples

Phishing samples come from the public research dataset [phishing_pot](https://github.com/rf-peixoto/phishing_pot). To download samples 001–030 in PowerShell:

```powershell
1..15  | ForEach-Object { $n = "{0:D3}" -f $_; Invoke-WebRequest "https://raw.githubusercontent.com/jimwangzx/phishing_pot/main/email/sample_$n.eml" -OutFile "samples\phishing\sample_$n.eml" }
16..30 | ForEach-Object { $n = "{0:D3}" -f $_; Invoke-WebRequest "https://raw.githubusercontent.com/jimwangzx/phishing_pot/main/email/sample_$n.eml" -OutFile "test_set\phishing\sample_$n.eml" }
```

⚠️ These are real phishing emails. Never open them in a mail client; only let the script read them.

## Project structure

```
email_header_analyzer.py   # detector (v2)
findings.md                # full analysis: every miss, patterns, false positive, results
samples/                   # training set: 001–015 (rules were built from these)
test_set/                  # held-out test set: 016–030 + real legit emails
```

## Data and privacy

- Phishing samples are from a public research dataset and are **not redistributed** in this repository; use the download commands above.
- The legitimate emails used for testing are the author's personal emails and are **not included**, to protect personal information.

## Limitations

- Small sample size (15 phishing and 7 legitimate emails in the test set). Results are directional, not statistically strong.
- Compromised legitimate accounts are hard to detect from headers alone.
- Keyword lists are English only.
- Domain comparisons use exact matching, which misfires on legitimate subdomains.

## Next steps (v3)

- Compare registered domains instead of full domains (fixes the known false positive)
- Add non-English lure keywords
- Add an LLM (OpenAI API) as a second opinion, and compare rules only, AI only, and combined
- Evaluate v3 on a fresh held-out set (samples 031–045) and new legitimate emails

## Skills demonstrated

Email authentication (SPF, DKIM, DMARC) · header forensics · detection engineering · precision/recall evaluation with a held-out test set · false positive root-cause analysis · Python · KQL / Microsoft Defender Advanced Hunting · threat intelligence (VirusTotal)
