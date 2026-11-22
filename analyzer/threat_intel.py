"""Vector 4 - Threat intelligence (VirusTotal API v3).

Free public API keys allow 4 requests per minute and 500 per day, so this
module first looks up an existing report and only submits the URL for a
fresh scan when VirusTotal has never seen it.
"""

import base64
import time
from datetime import datetime, timezone

import requests

from .utils import finding

VECTOR = "Threat intel"
API = "https://www.virustotal.com/api/v3"
TIMEOUT = 15


def _url_id(url: str) -> str:
    return base64.urlsafe_b64encode(url.encode()).decode().strip("=")


def _score_stats(stats: dict, findings: list):
    malicious = stats.get("malicious", 0)
    suspicious = stats.get("suspicious", 0)
    if malicious >= 5:
        findings.append(finding("Flagged malicious by many engines",
            f"{malicious} security vendors classify this URL as malicious.", 60, VECTOR))
    elif malicious >= 2:
        findings.append(finding("Flagged malicious by several engines",
            f"{malicious} security vendors classify this URL as malicious.", 45, VECTOR))
    elif malicious == 1:
        findings.append(finding("Flagged malicious by one engine",
            "1 security vendor classifies this URL as malicious. Treat as risky until checked.", 30, VECTOR))
    if suspicious:
        findings.append(finding("Flagged suspicious",
            f"{suspicious} vendor(s) mark this URL as suspicious.", min(10 * suspicious, 20), VECTOR))
    if malicious == 0 and suspicious == 0 and stats.get("harmless", 0) >= 50:
        findings.append(finding("Clean across vendors",
            f"{stats.get('harmless')} vendors report the URL as harmless.", -5, VECTOR))


def analyze(url: str, api_key: str) -> dict:
    result = {"vector": VECTOR, "status": "ok", "data": {"provider": "VirusTotal"}, "findings": []}
    data = result["data"]

    if not api_key:
        result["status"] = "skipped"
        data["note"] = "No VirusTotal API key configured."
        return result

    headers = {"x-apikey": api_key, "accept": "application/json"}
    try:
        resp = requests.get(f"{API}/urls/{_url_id(url)}", headers=headers, timeout=TIMEOUT)

        if resp.status_code == 200:
            attr = resp.json()["data"]["attributes"]
            stats = attr.get("last_analysis_stats", {})
            last = attr.get("last_analysis_date")
            flagged = {engine: r.get("result") for engine, r in attr.get("last_analysis_results", {}).items()
                       if r.get("category") in ("malicious", "suspicious")}
            data.update({
                "lookup": "existing report",
                "stats": stats,
                "engines_total": sum(stats.values()),
                "last_analysis_date": datetime.fromtimestamp(last, timezone.utc).isoformat() if last else None,
                "reputation": attr.get("reputation"),
                "times_submitted": attr.get("times_submitted"),
                "categories": attr.get("categories", {}),
                "final_url": attr.get("last_final_url"),
                "page_title": attr.get("title"),
                "flagging_engines": flagged,
                "threat_names": attr.get("threat_names", []),
                "content_type": (attr.get("last_http_response_headers") or {}).get("content-type")
                                or (attr.get("last_http_response_headers") or {}).get("Content-Type"),
                "permalink": f"https://www.virustotal.com/gui/url/{_url_id(url)}",
            })
            _score_stats(stats, result["findings"])
            return result

        if resp.status_code == 404:
            # Never seen before: submit and poll briefly for the analysis.
            sub = requests.post(f"{API}/urls", headers=headers, data={"url": url}, timeout=TIMEOUT)
            sub.raise_for_status()
            analysis_id = sub.json()["data"]["id"]
            data["lookup"] = "new submission"
            for _ in range(3):
                time.sleep(6)
                poll = requests.get(f"{API}/analyses/{analysis_id}", headers=headers, timeout=TIMEOUT)
                if poll.status_code != 200:
                    break
                attr = poll.json()["data"]["attributes"]
                if attr.get("status") == "completed":
                    stats = attr.get("stats", {})
                    flagged = {engine: r.get("result") for engine, r in attr.get("results", {}).items()
                               if r.get("category") in ("malicious", "suspicious")}
                    data.update({"stats": stats, "engines_total": sum(stats.values()),
                                 "flagging_engines": flagged})
                    _score_stats(stats, result["findings"])
                    return result
            data["note"] = "Submitted to VirusTotal; the scan was still queued. Re-run in a minute."
            result["findings"].append(finding("Unknown to threat intelligence",
                "VirusTotal had no prior record of this URL.", 5, VECTOR))
            return result

        if resp.status_code == 401:
            raise RuntimeError("The VirusTotal API key was rejected (401).")
        if resp.status_code == 429:
            raise RuntimeError("VirusTotal rate limit reached (free tier: 4 lookups per minute). Wait and retry.")
        raise RuntimeError(f"VirusTotal returned HTTP {resp.status_code}.")

    except Exception as exc:
        result["status"] = "error"
        data["error"] = str(exc)[:300]
        return result
