"""Threat-type classification: is a risky URL Phishing or Malware?

The risk score says HOW dangerous a URL is. This module says WHAT KIND of
threat it is, by weighing two separate bodies of evidence:

  Phishing  - the site imitates a trusted brand to steal logins, OTP/TAC codes,
              card details or other personal data.
  Malware   - the site delivers or hosts harmful software (executables,
              infected archives, malicious APKs, botnet loaders, C2 servers).

Each indicator found by the four vectors contributes evidence points to one
or both types. VirusTotal engine labels and categories count as the strongest
evidence because they come from independent security vendors.
"""

from . import lexical, threat_intel, whois_lookup

PHISHING = "Phishing"
MALWARE = "Malware"
BOTH = "Phishing & Malware"
UNDETERMINED = "Undetermined"
NONE = "No threat detected"

DESCRIPTIONS = {
    PHISHING: "A fake page built to trick you into entering passwords, banking details, "
              "OTP/TAC codes or personal information.",
    MALWARE: "A link that delivers or hosts harmful software, such as a virus, trojan, "
             "ransomware or malicious app, that can infect the device.",
    BOTH: "Signs of both a credential-stealing page and harmful software delivery.",
    UNDETERMINED: "The URL is risky, but the evidence does not clearly point to phishing "
                  "or to malware.",
    NONE: "No strong phishing or malware indicators were found. This is not a guarantee: a brand-new "
          "scam link can look clean, so still be careful with links you did not expect.",
}

# Lexical/WHOIS indicator -> (phishing points, malware points)
INDICATOR_WEIGHTS = {
    # Phishing: impersonation and credential harvesting
    "Brand name outside its official domain": (30, 0),
    "Possible typosquatting": (30, 0),
    "Punycode (IDN) domain": (20, 0),
    "Deceptive domain prefix": (30, 0),
    "Brand domain with a fake ending": (20, 0),
    "Brand page on free hosting": (20, 0),
    "Login page in website system folder": (30, 0),
    "Free hosting or website builder": (15, 5),
    "User-made page on a trusted platform": (10, 5),
    "IPFS gateway": (20, 5),
    "'@' symbol in authority": (15, 0),
    "Multiple hyphens in hostname": (5, 0),
    "Excessive subdomains": (10, 0),
    "Many subdomains": (5, 0),
    "URL embedded in path or query": (5, 0),
    "Embedded redirect ('//' in path)": (5, 0),
    # Malware: payload delivery and command-and-control
    "Disguised executable (double extension)": (0, 45),
    "Executable or archive download": (0, 35),
    "IP address used as host": (10, 10),
    "Non-standard port": (5, 10),
    "High-randomness domain name": (0, 20),
    "Digit-heavy hostname": (0, 5),
    # Shared signals
    "URL shortener": (5, 5),
    "High-abuse top-level domain": (5, 5),
    "Newly registered domain": (10, 5),
}

PHISH_WORDS = ("phish", "fraud", "scam", "fake", "credential", "spoof")
MALWARE_WORDS = ("malware", "trojan", "virus", "worm", "ransom", "botnet", "spyware",
                 "adware", "miner", "exploit", "dropper", "backdoor", "infected", "c2",
                 "command and control", "malicious web", "downloader")
EXECUTABLE_CONTENT = ("application/x-msdownload", "application/x-dosexec", "application/octet-stream",
                      "application/vnd.android.package-archive", "application/x-executable",
                      "application/zip", "application/x-rar", "application/x-7z", "application/java-archive")


def _add(evidence, kind, source, reason, points):
    evidence.append({"type": kind, "source": source, "reason": reason, "points": points})


def classify(results: list, risk_verdict: str) -> dict:
    by_vector = {r["vector"]: r for r in results}
    evidence = []

    # A link that downloads a program is a malware delivery, even when it uses a
    # brand name: the brand is the bait to make the victim run the file.
    payload_checks = {"Disguised executable (double extension)", "Executable or archive download"}
    impersonation_checks = {"Brand name outside its official domain", "Possible typosquatting",
                            "Punycode (IDN) domain", "Deceptive domain prefix", "Brand domain with a fake ending", "Brand page on free hosting",
                            "Login page in website system folder"}
    delivers_file = any(f["check"] in payload_checks for r in results for f in r["findings"])

    # 1. Indicators raised by the lexical and WHOIS vectors.
    for r in results:
        if r["vector"] not in (lexical.VECTOR, whois_lookup.VECTOR):
            continue
        for f in r["findings"]:
            if f["check"] == "Credential-lure keywords":
                words = r["data"].get("suspicious_keywords", [])
                if delivers_file:
                    continue  # lure words on a file download are not a login page
                _add(evidence, PHISHING, r["vector"], f"Login/payment lure words: {', '.join(words)}",
                     min(12 * len(words), 30))
                continue
            if f["check"] == "Malware-lure keywords":
                words = r["data"].get("malware_keywords", [])
                _add(evidence, MALWARE, r["vector"], f"Download/crack lure words: {', '.join(words)}",
                     min(8 * len(words), 25))
                continue
            p, m = INDICATOR_WEIGHTS.get(f["check"], (0, 0))
            if delivers_file and f["check"] in impersonation_checks:
                _add(evidence, MALWARE, r["vector"], f"{f['check']} used as bait for a file download", 15)
                continue
            if p:
                _add(evidence, PHISHING, r["vector"], f["check"], p)
            if m:
                _add(evidence, MALWARE, r["vector"], f["check"], m)

    # 2. Threat intelligence labels from independent security vendors.
    ti = by_vector.get(threat_intel.VECTOR, {}).get("data", {})
    labels = [str(v).lower() for v in (ti.get("flagging_engines") or {}).values() if v]
    phish_engines = sum(1 for v in labels if any(w in v for w in PHISH_WORDS))
    malware_engines = sum(1 for v in labels if any(w in v for w in MALWARE_WORDS))
    if phish_engines:
        _add(evidence, PHISHING, "Threat intel",
             f"{phish_engines} vendor(s) labelled it phishing/fraud", min(15 * phish_engines, 60))
    if malware_engines:
        _add(evidence, MALWARE, "Threat intel",
             f"{malware_engines} vendor(s) labelled it malware", min(15 * malware_engines, 60))

    categories = " | ".join(str(v).lower() for v in (ti.get("categories") or {}).values())
    cat_phish = any(w in categories for w in PHISH_WORDS)
    cat_malware = any(w in categories for w in MALWARE_WORDS)
    if cat_phish:
        _add(evidence, PHISHING, "Threat intel", "Vendor category: phishing/fraud site", 20)
    if cat_malware:
        _add(evidence, MALWARE, "Threat intel", "Vendor category: malware/malicious site", 20)

    threat_names = [str(t) for t in (ti.get("threat_names") or [])]
    if threat_names:
        _add(evidence, MALWARE, "Threat intel", f"Known threat name(s): {', '.join(threat_names[:5])}", 30)

    content_type = (ti.get("content_type") or "").lower()
    if any(content_type.startswith(c) for c in EXECUTABLE_CONTENT):
        _add(evidence, MALWARE, "Threat intel", f"Server returned a file download ({content_type})", 35)

    phishing_score = min(100, sum(e["points"] for e in evidence if e["type"] == PHISHING))
    malware_score = min(100, sum(e["points"] for e in evidence if e["type"] == MALWARE))
    vendor_backed = bool(phish_engines or malware_engines or threat_names or cat_phish or cat_malware)

    # 3. Decide the threat type.
    if risk_verdict == "Benign":
        threat_type = NONE
    elif phishing_score >= 25 and malware_score >= 25 and \
            min(phishing_score, malware_score) >= 0.6 * max(phishing_score, malware_score):
        threat_type = BOTH
    elif phishing_score >= 15 and phishing_score > malware_score:
        threat_type = PHISHING
    elif malware_score >= 15 and malware_score > phishing_score:
        threat_type = MALWARE
    else:
        threat_type = UNDETERMINED

    # 4. Confidence: how clearly the evidence separates the two types.
    gap = abs(phishing_score - malware_score)
    top = max(phishing_score, malware_score)
    if threat_type in (NONE, UNDETERMINED):
        confidence = "-"
    elif (top >= 50 and gap >= 25) or (vendor_backed and gap >= 15):
        confidence = "High"
    elif top >= 30 and gap >= 10:
        confidence = "Medium"
    else:
        confidence = "Low"

    return {
        "threat_type": threat_type,
        "description": DESCRIPTIONS[threat_type],
        "confidence": confidence,
        "phishing_score": phishing_score,
        "malware_score": malware_score,
        "vendor_backed": vendor_backed,
        "delivers_file": delivers_file,
        "evidence": sorted(evidence, key=lambda e: -e["points"]),
    }
