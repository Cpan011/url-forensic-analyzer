"""Rule-based forensic risk scoring and the engine that runs every vector."""

import hashlib
import json
import platform
import uuid
from datetime import datetime, timezone

from . import classifier, lexical, redirects, ssl_inspector, threat_intel, whois_lookup
from .utils import defang, finding, normalize_url

TOOL_NAME = "Development of a Phishing and Malicious URL Forensic Analyzer"
TOOL_VERSION = "1.0.0"

BENIGN_MAX = 29       # 0-29   Benign
SUSPICIOUS_MAX = 59   # 30-59  Suspicious, 60-100 Malicious


def classify(score: int) -> str:
    if score <= BENIGN_MAX:
        return "Benign"
    if score <= SUSPICIOUS_MAX:
        return "Suspicious"
    return "Malicious"


def score(results: list) -> dict:
    findings = [f for r in results for f in r["findings"]]
    raw = sum(f["points"] for f in findings)
    total = max(0, min(100, raw))
    verdict = classify(total)
    override = None

    # Hard rule: strong threat-intel consensus is conclusive on its own.
    ti = next((r for r in results if r["vector"] == threat_intel.VECTOR), None)
    malicious_hits = (ti or {}).get("data", {}).get("stats", {}).get("malicious", 0)
    if malicious_hits >= 3 and verdict != "Malicious":
        verdict, total = "Malicious", max(total, SUSPICIOUS_MAX + 1)
        override = f"Raised to Malicious: {malicious_hits} VirusTotal security vendors flag this URL."
    elif malicious_hits >= 2 and verdict == "Benign":
        verdict, total = "Suspicious", max(total, BENIGN_MAX + 1)
        override = f"Raised to Suspicious: {malicious_hits} VirusTotal security vendor(s) flag this URL."

    by_vector = {}
    for f in findings:
        by_vector[f["vector"]] = by_vector.get(f["vector"], 0) + f["points"]

    classification = classifier.classify(results, verdict)

    return {
        "score": total,
        "threat_type": classification["threat_type"],
        "classification": classification,
        "raw_points": raw,
        "verdict": verdict,
        "override": override,
        "points_by_vector": by_vector,
        "indicators": sorted(findings, key=lambda f: -f["points"]),
        "risk_indicator_count": sum(1 for f in findings if f["points"] > 0),
    }


def evidence_hash(record: dict) -> str:
    """SHA-256 of the canonical evidence record (excluding the hash itself)."""
    body = {k: v for k, v in record.items() if k != "integrity"}
    canonical = json.dumps(body, sort_keys=True, default=str, separators=(",", ":"))
    return hashlib.sha256(canonical.encode()).hexdigest()


def run_analysis(raw_url: str, vt_key: str = "", case_ref: str = "", examiner: str = "",
                 enable_whois=True, enable_ssl=True, enable_ti=True, expand_short_links=True,
                 progress=None) -> dict:
    """Run every enabled vector and return a complete, hash-sealed evidence record."""
    started = datetime.now(timezone.utc)
    url, scheme_given = normalize_url(raw_url)

    def step(label):
        if progress:
            progress(label)

    results = []
    step("Inspecting URL structure")
    first = lexical.analyze(url, scheme_given)
    redirect = None
    analyzed = url

    # A short link hides its destination: reveal it, then analyze the destination.
    if expand_short_links and any(f["check"] == "URL shortener" for f in first["findings"]):
        step("Revealing where the short link leads")
        redirect = redirects.expand(url)
        if redirect["final_url"] != url:
            analyzed = redirect["final_url"]
            first = lexical.analyze(analyzed, True)
            first["findings"].append(finding("Short link hides the destination",
                f"The short link redirects through {len(redirect['chain']) - 1} hop(s) to {defang(analyzed)}. "
                "The destination was analyzed instead.", 10, lexical.VECTOR))
    results.append(first)
    url_for_checks = analyzed

    if enable_whois:
        step("Querying WHOIS registry")
        results.append(whois_lookup.analyze(url_for_checks))
    if enable_ssl:
        step("Inspecting SSL/TLS certificate")
        results.append(ssl_inspector.analyze(url_for_checks))
    if enable_ti:
        step("Checking threat intelligence")
        results.append(threat_intel.analyze(url_for_checks, vt_key))

    step("Calculating risk score")
    assessment = score(results)
    finished = datetime.now(timezone.utc)

    record = {
        "case": {
            "case_reference": case_ref or "N/A",
            "examiner": examiner or "N/A",
            "examination_id": str(uuid.uuid4()),
            "started_utc": started.isoformat(timespec="seconds"),
            "finished_utc": finished.isoformat(timespec="seconds"),
            "duration_seconds": round((finished - started).total_seconds(), 2),
            "tool": f"{TOOL_NAME} v{TOOL_VERSION}",
            "environment": f"Python {platform.python_version()} on {platform.system()}",
        },
        "target": {
            "submitted_input": raw_url,
            "normalized_url": url,
            "defanged_url": defang(url),
            "url_sha256": hashlib.sha256(url.encode()).hexdigest(),
            "analyzed_url": defang(analyzed),
            "redirect_chain": [defang(u) for u in redirect["chain"]] if redirect else [],
            "redirect_note": (redirect or {}).get("error") or "",
        },
        "assessment": assessment,
        "vectors": {r["vector"]: {"status": r["status"], "data": r["data"]} for r in results},
    }
    record["integrity"] = {"algorithm": "SHA-256", "evidence_hash": evidence_hash(record)}
    return record
