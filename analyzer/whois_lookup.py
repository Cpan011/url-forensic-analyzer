"""Vector 2 - WHOIS metadata analysis (domain age, registrar, expiry)."""

from datetime import datetime, timezone

from urllib.parse import urlparse

from .intel_lists import hosting_platform
from .utils import finding, get_host, is_ip, registered_domain

VECTOR = "WHOIS"

try:
    import whois  # package: python-whois
except ImportError:  # pragma: no cover
    whois = None


def _first(value):
    if isinstance(value, (list, tuple)):
        value = [v for v in value if v]
        return value[0] if value else None
    return value


def _as_utc(value):
    value = _first(value)
    if not isinstance(value, datetime):
        return None
    if value.tzinfo is None:
        value = value.replace(tzinfo=timezone.utc)
    return value.astimezone(timezone.utc)


def _text(value):
    value = _first(value)
    return str(value) if value else None


def analyze(url: str) -> dict:
    host = get_host(url)
    domain = registered_domain(host)
    result = {"vector": VECTOR, "status": "ok", "data": {"queried_domain": domain}, "findings": []}

    if is_ip(host):
        result["status"] = "skipped"
        result["data"]["note"] = "WHOIS domain lookup does not apply to a raw IP address."
        return result
    platform = hosting_platform(host, domain, urlparse(url).path or "/")
    if platform:
        result["status"] = "skipped"
        result["data"]["note"] = (f"This page is hosted on {platform[1]}. That platform's registration date "
                                  "says nothing about who made this page, so domain age was not used.")
        return result
    if whois is None:
        result["status"] = "error"
        result["data"]["error"] = "python-whois is not installed."
        return result

    try:
        record = whois.whois(domain)
    except Exception as exc:  # network errors, unsupported TLD servers, parse errors
        result["status"] = "error"
        result["data"]["error"] = f"{type(exc).__name__}: {exc}"[:300]
        result["findings"].append(finding("WHOIS lookup failed",
            "No registration data could be retrieved, so domain age is unknown.", 5, VECTOR))
        return result

    now = datetime.now(timezone.utc)
    created = _as_utc(record.get("creation_date"))
    expires = _as_utc(record.get("expiration_date"))
    updated = _as_utc(record.get("updated_date"))

    data = result["data"]
    data.update({
        "registrar": _text(record.get("registrar")),
        "creation_date": created.isoformat() if created else None,
        "expiration_date": expires.isoformat() if expires else None,
        "updated_date": updated.isoformat() if updated else None,
        "registrant_country": _text(record.get("country")),
        "registrant_org": _text(record.get("org")),
        "name_servers": sorted({str(n).lower() for n in (record.get("name_servers") or [])})
                        if isinstance(record.get("name_servers"), (list, tuple, set))
                        else _text(record.get("name_servers")),
        "domain_age_days": (now - created).days if created else None,
        "days_until_expiry": (expires - now).days if expires else None,
    })

    if not created and not data["registrar"]:
        result["status"] = "error"
        data["error"] = "The WHOIS server returned no usable registration fields."
        result["findings"].append(finding("WHOIS record empty",
            "The registry returned no creation date or registrar.", 5, VECTOR))
        return result

    age = data["domain_age_days"]
    if age is None:
        result["findings"].append(finding("Creation date hidden",
            "The registry did not publish a creation date.", 5, VECTOR))
    elif age < 30:
        result["findings"].append(finding("Newly registered domain",
            f"Registered {age} day(s) ago. Most phishing domains are used within weeks of registration.", 25, VECTOR))
    elif age < 180:
        result["findings"].append(finding("Young domain",
            f"Registered {age} days ago (under 6 months).", 10, VECTOR))
    elif age >= 365 * 2:
        result["findings"].append(finding("Established domain",
            f"Registered {age // 365} years ago.", -10, VECTOR))

    left = data["days_until_expiry"]
    if left is not None and age is not None and age < 365 and 0 <= left < 365:
        result["findings"].append(finding("Short registration period",
            "Registered for one year or less, typical of throwaway domains.", 5, VECTOR))
    if left is not None and left < 0:
        result["findings"].append(finding("Registration expired",
            f"The registration expired {abs(left)} day(s) ago.", 10, VECTOR))

    privacy_words = ("privacy", "redacted", "proxy", "withheld", "protect")
    org = (data.get("registrant_org") or "").lower()
    if any(w in org for w in privacy_words):
        result["findings"].append(finding("Registrant identity hidden",
            "WHOIS privacy is enabled. Common for legitimate sites too, so not scored.", 0, VECTOR))

    return result
