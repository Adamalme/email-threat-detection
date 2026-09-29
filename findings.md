# Detection Findings

## Run 1 (detector v1)

- Phishing samples: 16 (15 from the public phishing_pot dataset + 1 test email)
- Legit samples: 0 (to be added)
- Caught: 9 | Missed: 7 | **Recall: 56%**
- Precision: 100%, but not meaningful yet because no legit emails were tested

## Missed samples

### sample_001 (score 0)
- From: "Nerena Groen" <contact@123gereedschap.nl> (a Dutch tool shop's domain)
- Return-Path: same domain; no Reply-To
- SPF: pass | DKIM: none | DMARC: bestguesspass
- Subject: 💕 "Only view this email if you're an adult" (Dutch)
- Type: adult/romance scam sent from a likely compromised legitimate domain
- Why missed: authentication passed, no header mismatches, Dutch language (keyword list is English only), display name is a personal name

### sample_005
- From: "MetaMask (MVS)" <87357344@mymts.net> (display name was Base64-encoded)
- Subject: "[## Metamask ##] You have a new update"
- Type: crypto wallet impersonation from a numbered account at an internet provider
- Why missed: MetaMask was not in the brand list; "new update" was not a keyword

### sample_006
- From: "2U" <random Gmail address with a +tag>
- Subject: "OrderConfirmation:93345881"
- Type: fake order confirmation (refund/callback scam) from a free email account
- Why missed: no rule for business-style emails sent from free email providers

### sample_007
- From: "Ledger Security" <ledger@secureliveupdates.com>
- Return-Path: rsgsv.net (Mailchimp's sending infrastructure)
- Subject: "[29th, August] Reminder from Ledger"
- Type: crypto wallet impersonation sent through an abused legitimate marketing service
- Why missed: Ledger was not in the brand list; only the Return-Path mismatch fired (score 1)

### sample_008
- From: "Metamask_TeamSupport31612220446" <metamask-updates-action@netwrksecurity.com>
- Subject: "Alerts"
- Type: MetaMask impersonation from a fake-sounding domain ("netwrk"), with a long number in the display name
- Why missed: MetaMask was not in the brand list; no rule for digit strings in display names

### sample_009
- From: "Karen Simser" <ksimser@rmh.org>
- Subject: "AW" (German email shorthand for "Reply")
- Type: likely a compromised real account sending a fake reply
- Why missed: legitimate domain, authentication passes, almost no content signals

### sample_010
- From: "Stellar Foundation" <herb@southernheritagecc.com>
- Subject: "Earn XLM by staking your assets"
- Type: crypto staking scam from an unrelated, likely compromised domain
- Why missed: Stellar was not in the brand list; "staking" was not a keyword

## Patterns across the misses

1. **Crypto brand impersonation** (005, 007, 008, 010): MetaMask, Ledger, and Stellar were not in the brand list, so the brand rule never fired. This was the biggest gap.
2. **Compromised or unrelated legitimate senders** (001, 009, 010): real domains pass SPF/DKIM/DMARC, so authentication rules cannot catch them.
3. **Free email pretending to be a business** (006): real companies do not send order confirmations from Gmail.
4. **Abused legitimate services** (007): scammers send through Mailchimp and similar services, so the technical parts look clean.
5. **Keyword gaps and language** (001, 005, 010): the keyword list focused on English BEC wording and missed phishing/crypto terms and non-English scams.

## Other findings

- **Reputation lag:** the sender domain, Reply-To domain, and landing page of a confirmed casino scam all scored 0/92 on VirusTotal. "No detections" means "not known to be bad," not "safe."
- **Lab baseline:** in the Microsoft Defender lab tenant, all 52 inbound emails over 30 days passed SPF/DKIM/DMARC (51 pass, 1 bestguesspass). The KQL detection correctly returned 0 alerts on clean traffic.

## Rules added in v2

| Rule | Weight | Addresses |
|---|---|---|
| Brand in display name but sender is not that brand's real domain (brand list expanded with crypto and common brands) | HIGH (3) | Pattern 1 |
| Long digit string in display name | MEDIUM (2) | sample_008 |
| Sender address made only of digits | LOW (1) | sample_005 |
| Business-style subject from a free email provider | HIGH (3) | Pattern 3 |
| Missing DKIM signature | LOW (1) | weak signal |
| Phishing/crypto lure keywords | MEDIUM (2) | Pattern 5 |

## Run 2 (detector v2)

### Training set (samples 001–015 + test email)
- Recall: **94%** (15/16), up from 56% in Run 1
- Still missed: sample_001 (Dutch adult scam from a compromised legitimate domain)

### Held-out test set (samples 016–030 + 7 real emails, never used to build rules)
- Phishing: 15 samples | Legit: 7 real emails (Coinbase, GitHub, LinkedIn, Amazon, Handshake, university, identity verification)
- **Recall: 87%** (13/15) | **Precision: 93%** (13/14)
- True negatives: 6/7 real emails correctly passed
- Missed: sample_019, sample_021 (score 2, just below the threshold of 3)
- Coinbase email correctly passed: the brand rule allows real subdomains (mail.coinbase.com)
- Generalization gap: 94% → 87%, showing the rules learned general patterns rather than memorizing samples

### False positive: Handshake notification (score 3)
- Rule fired: Reply-To domain (joinhandshake.com) differs from From (notifications.joinhandshake.com)
- Root cause: the rule compares full domains exactly, so a legitimate subdomain of the same organization counts as a mismatch
- Fix for v3: compare registered domains (e.g., with tldextract) instead of full domains. This likely also reduces the weak Return-Path signal on legitimate mail.
- Not fixed in v2, to keep the test set results honest

### Summary

| | Run 1 (v1) | Run 2 (v2) training | Run 2 (v2) held-out test |
|---|---|---|---|
| Recall | 56% | 94% | **87%** |
| Precision | not measured | not measured | **93%** |
| False positives | not measured | not measured | 1 of 7 legit |

## Known limitations

- Compromised legitimate accounts (001, 009) remain hard to detect from headers alone.
- Keyword lists are English only.
- Small sample size (15 phishing and 7 legit in the test set). Results are directional, not statistically strong.
- Domain comparisons use exact matching, which misfires on legitimate subdomains (see the Handshake false positive).

## Next steps (v3)

- Compare registered domains instead of full domains (fixes the Handshake false positive)
- Add non-English lure keywords
- Experiment with an LLM (OpenAI API) as a second opinion, comparing rules only, AI only, and combined
- Evaluate v3 on a fresh held-out set (samples 031–045) plus new legit emails
