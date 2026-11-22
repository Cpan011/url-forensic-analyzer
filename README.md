# Development of a Phishing and Malicious URL Forensic Analyzer

A responsive, web-based forensic triage tool that examines a suspicious URL through four
analysis vectors, produces a rule-based risk score (Benign / Suspicious / Malicious),
tells you what kind of threat the link is (Phishing or Malware), and exports the findings as a PDF report plus a hash-sealed JSON evidence file.

Final project, Diploma in Computer Forensics (DCF), Management and Science University.

## How it maps to the project objectives

| Objective (Chapter 1.3) | Where it lives |
|---|---|
| 1. Multi-layered forensic extraction engine | `analyzer/lexical.py`, `analyzer/whois_lookup.py`, `analyzer/ssl_inspector.py`, `analyzer/threat_intel.py` |
| 2. Rule-based risk-scoring algorithm | `analyzer/scoring.py` |
| 3. Responsive cross-platform UI with Streamlit | `app.py`, `.streamlit/config.toml` |
| 4. Automated PDF forensic reporting | `analyzer/report.py` (+ `verify_evidence.py` for integrity checks) |

## Project structure

```
phishing-and-malicious-url-forensic-analyzer/
├── app.py                    Streamlit web interface
├── analyzer/
│   ├── utils.py              URL parsing, defanging, entropy, SSRF guard
│   ├── lexical.py            Vector 1: URL structure, brand impersonation, typosquatting, homographs
│   ├── intel_lists.py        Brands, free-hosting platforms, lure words, risky TLDs (easy to extend)
│   ├── redirects.py          Reveals where short links (bit.ly, tinyurl) lead, headers only
│   ├── whois_lookup.py       Vector 2: domain age, registrar, expiry
│   ├── ssl_inspector.py      Vector 3: certificate trust, issuer, validity, fingerprint
│   ├── threat_intel.py       Vector 4: VirusTotal API v3 reputation
│   ├── classifier.py         Threat type: Phishing vs Malware, with evidence
│   ├── scoring.py            Risk scoring + evidence record + SHA-256 seal
│   └── report.py             PDF report generator (ReportLab)
├── verify_evidence.py        Checks an exported JSON evidence file against its hash
├── .vscode/
│   ├── launch.json           F5 runs the app and opens the browser
│   └── settings.json         Uses the project's .venv automatically
├── requirements.txt
└── .streamlit/
    ├── config.toml           Theme
    └── secrets.toml.example  Template for the VirusTotal API key
```

## Run it on your computer (Windows, VS Code)

Requires **Python 3.12** (3.13/3.14 are not supported by the pinned libraries).

### First time only

1. Open this folder (the one that contains `app.py`) in VS Code with **File > Open Folder**.
2. Open the terminal (**Ctrl+`**) and run, one at a time:
   ```
   py -3.12 -m venv .venv
   .venv\Scripts\activate
   python -m pip install -r requirements.txt
   ```
3. Press **Ctrl+Shift+P**, choose **Python: Select Interpreter**, and pick the `.venv` one (3.12).

### Every time

- **Easiest:** press **F5**. VS Code starts the app ("Run URL analyzer" in `.vscode/launch.json`) and
  opens it in your browser. Press **Shift+F5** to stop it.
- **Or in the terminal:** `python -m streamlit run app.py`, then open http://localhost:8501.
  Press **Ctrl+C** in the terminal to stop it.

Always use `python -m pip` and `python -m streamlit` (not `pip` / `streamlit`), because Windows
Smart App Control blocks the small `.exe` launchers inside `.venv\Scripts`.

To try it on your phone, connect the phone to the same Wi-Fi and open the "Network URL" that
Streamlit prints in the terminal.

## Get a VirusTotal API key (free)

1. Sign up at https://www.virustotal.com.
2. Click your profile picture → **API key**, and copy it.
3. Either paste it into the sidebar each session, or copy `.streamlit/secrets.toml.example`
   to `.streamlit/secrets.toml` and put the key there. `secrets.toml` is in `.gitignore`,
   so it will not be uploaded to GitHub.

Free keys allow 4 lookups per minute and 500 per day.

## Deploy to Streamlit Community Cloud (public link for desktop and Android)

1. Create a GitHub repository and upload this folder (not `secrets.toml`).
2. Go to https://share.streamlit.io, sign in with GitHub, click **Create app**.
3. Pick the repository, branch `main`, main file `app.py`. Under **Advanced settings**
   choose Python 3.12 and paste into **Secrets**:
   ```
   VT_API_KEY = "your-key-here"
   ```
4. Click **Deploy**. You get a link like `https://your-app-name.streamlit.app`.

## Risk scoring

Each check adds (or, for trust signals, subtracts) points. The total is clamped to 0–100.

| Score | Classification |
|---|---|
| 0–29 | Benign |
| 30–59 | Suspicious |
| 60–100 | Malicious |

VirusTotal override: 3 or more security vendors flagging the URL raises it to **Malicious**;
1–2 vendors raise a Benign result to at least **Suspicious**.

Main weights (full list in each vector file):

| Indicator | Points |
|---|---|
| VirusTotal: ≥5 / 2–4 / 1 vendor(s) flag it | +60 / +45 / +30 |
| Typosquatting (`maybannk2u`) | +30 |
| IPFS gateway | +30 |
| Brand name in the hostname but not the brand's real domain | +25 |
| Newly registered domain (< 30 days), expired/untrusted certificate | +25 |
| Direct `.exe`/`.apk`/`.zip` download | +25 |
| Fake domain prefix (`paypal.com-verify.info`) | +20 |
| Login/brand page inside `/wp-content/` etc. of a hacked site | +20 |
| IP address as host, self-signed certificate | +20 |
| Free hosting / website builder (`vercel.app`, `weebly.com`, `pages.dev` …) | +15 |
| Brand page on free hosting (extra) | +15 |
| Brand's own name with a fake ending (`roblox.com.ge`) | +15 |
| Short link | +15 (or the destination is revealed and analyzed) |
| Lure words: login, verify, otp, tac, kyc, saman, bayar, sahkan … | +5 each, max +20 |
| Official brand domain / domain older than 2 years | −15 / −10 |

## Threat-type classification (Phishing vs Malware)

The risk score says how dangerous a URL is; `analyzer/classifier.py` says what kind of threat it is.
Every indicator adds evidence points to a **phishing score** and/or a **malware score** (0–100):

| Phishing evidence | Malware evidence |
|---|---|
| Brand name on the wrong domain, typosquatting, look-alike (punycode) letters | Link straight to `.exe`, `.apk`, `.msi`, `.zip`, `.js`, `.iso` etc. |
| Login/payment lure words (login, verify, otp, tac, billing…) | Disguised files such as `invoice.pdf.exe` |
| Fake prefixes (`paypal.com-verify.info`), brand pages on free hosting, IPFS pages |
| Login pages hidden in `/wp-content/` of hacked websites |
| `@` trick, deep subdomains, embedded redirects | Crack/keygen/setup/download lure words, botnet paths (`/bins/`) |
| VirusTotal vendors labelling it phishing/fraud | Raw-IP host on a non-standard port, random (DGA) domain names |
| | VirusTotal malware labels, known threat names, file-download content type |

Special rule: when the link downloads a file (`.exe`, `.apk`, …), a brand name in the URL counts
as **malware bait**, not phishing, because the goal is to make the victim install the file (for
example a fake "WhatsApp Gold" APK).

Decision: Benign risk → **No threat detected**. Otherwise the higher score wins (**Phishing** or
**Malware**); if both are strong and close → **Phishing & Malware**; if neither reaches 15 →
**Undetermined**. Confidence (High/Medium/Low) depends on the gap between the two scores and whether
VirusTotal vendors back it up.

## Why a real scam link might still say "No threat detected"

Modern phishing often uses a free website builder and no brand name, e.g. a page called
`my-portal-2026.vercel.app`. Nothing in the address gives it away, so only **VirusTotal** can
catch it once security vendors have seen it. That is why:

- the app shows a yellow warning whenever VirusTotal was **not** used (no key, rate limit, error);
- the result says **"No threat detected"**, never "safe";
- a brand-new link VirusTotal has never seen is submitted for scanning; analyze it again a minute
  later for the vendor results.

## Forensic features

- **Passive only.** The page is never downloaded or rendered; only the URL text, WHOIS, a TLS
  handshake, the redirect header of short links and the VirusTotal API are used, so live phishing
  links can be examined safely.
- **Short-link reveal.** bit.ly/tinyurl links are followed hop by hop (headers only, max 5 hops);
  the full redirect chain is recorded as evidence and the real destination is analyzed.
- **Defanged output.** URLs are shown as `hxxps://example[.]com` in the UI and report.
- **Evidence integrity.** Every examination is sealed with a SHA-256 hash of the canonical JSON
  record. Run `python verify_evidence.py url-evidence-xxxx.json` to prove it has not been altered.
- **Case metadata.** Case reference, examiner name, examination ID and UTC timestamps are
  recorded in every report.
- **SSRF guard.** Hosts that resolve to private or loopback addresses are not probed.

## Sample URLs for your demo

| URL | Risk level | Threat type |
|---|---|---|
| `https://www.maybank2u.com.my` | Benign | No threat detected |
| `https://www.jpj.gov.my` | Benign | No threat detected |
| `http://paypa1-secure-login.xyz/verify/account` | Malicious | Phishing |
| `https://paypal.com-account-verify.info/` | Malicious | Phishing (fake prefix) |
| `https://maybank2u-secure.web.app/` | Malicious | Phishing (free hosting) |
| `https://metamask-wallet-restore.vercel.app/` | Malicious | Phishing (free hosting) |
| `https://sites.google.com/view/microsoft-365-sharedfile` | Suspicious | Phishing |
| `https://jpj-gov-my.top/bayar` | Suspicious | Phishing (Malay lure words) |
| `https://www.maybannk2u.com.my/` | Suspicious | Phishing (typosquatting) |
| `https://sunrisebakery-ny.com/wp-content/plugins/akismet/sso/microsoft/index.php` | Suspicious | Phishing (hacked site) |
| `http://free-software-download.top/adobe-crack/setup.exe` | Malicious | Malware |
| `https://maybank2u-update.firebaseapp.com/MAE_Update.apk` | Malicious | Malware (fake app) |
| `https://drive-files.xyz/payment-invoice.pdf.exe` | Suspicious | Malware (disguised file) |
| `http://45.83.122.10:8080/bins/mozi.m` | Suspicious | Malware (botnet) |

These are made-up addresses that follow real attack patterns, so they are safe to type.
Results for live sites can be higher than this table, because WHOIS (new domain), SSL (no or bad
certificate) and VirusTotal add their own evidence.

For real malware URLs, use https://urlhaus.abuse.ch (copy the text, never open the links).

For real, currently active phishing URLs to test against, use the public feeds at
https://openphish.com or https://phishtank.org (copy the text, do not open the links).

## Limitations

As described in Chapter 1.6: WHOIS and VirusTotal depend on third-party availability and
free-tier rate limits; some country registries (including some `.my` domains) return limited
WHOIS data; cloaked pages that only reveal themselves to real browsers need dynamic analysis,
which is out of scope; and the tool needs an internet connection.
