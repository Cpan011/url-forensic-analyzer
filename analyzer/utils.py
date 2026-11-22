"""Shared helper functions used by every analysis vector."""

import ipaddress
import math
import socket
from collections import Counter
from urllib.parse import urlparse

# Second-level public suffixes, so "maybank2u.com.my" is treated as the
# registered domain instead of "com.my".
MULTI_PART_SUFFIXES = {
    "com.my", "net.my", "org.my", "edu.my", "gov.my", "name.my", "mil.my",
    "co.uk", "org.uk", "ac.uk", "gov.uk", "com.au", "net.au", "org.au",
    "co.id", "or.id", "go.id", "com.sg", "edu.sg", "gov.sg", "com.cn",
    "co.jp", "co.in", "com.br", "co.nz", "co.za", "com.ph", "com.vn",
    "co.th", "com.hk", "com.tw", "co.kr",
}


GENERIC_SLDS = {"com", "net", "org", "gov", "edu", "co", "ac", "or", "go", "ne", "mil", "nic", "info", "biz"}


def normalize_url(raw: str):
    """Return (url, scheme_was_given). Adds http:// when no scheme is typed."""
    url = raw.strip()
    has_scheme = "://" in url.split("?")[0]
    if not has_scheme:
        url = "http://" + url
    return url, has_scheme


def get_host(url: str) -> str:
    return (urlparse(url).hostname or "").lower().rstrip(".")


def is_ip(host: str) -> bool:
    try:
        ipaddress.ip_address(host)
        return True
    except ValueError:
        pass
    # Hex / decimal encoded IPs such as http://0xC0A80001 or http://3232235521
    try:
        if host.startswith("0x"):
            int(host, 16)
            return True
        if host.isdigit() and int(host) < 2**32:
            return True
    except ValueError:
        pass
    return False


def registered_domain(host: str) -> str:
    """Best-effort registrable domain, e.g. login.secure.paypal.com -> paypal.com"""
    if not host or is_ip(host):
        return host
    labels = host.split(".")
    if len(labels) >= 3 and ".".join(labels[-2:]) in MULTI_PART_SUFFIXES:
        return ".".join(labels[-3:])
    # Generic country second-level domains such as com.ge, gov.ph, co.ke
    if len(labels) >= 3 and len(labels[-1]) == 2 and labels[-2] in GENERIC_SLDS:
        return ".".join(labels[-3:])
    return ".".join(labels[-2:])


def domain_label(reg_domain: str) -> str:
    """The name part of a registered domain: paypal.com -> paypal"""
    return reg_domain.split(".")[0] if reg_domain else ""


def defang(url: str) -> str:
    """Make a URL non-clickable for safe inclusion in reports."""
    return (url.replace("http://", "hxxp://")
               .replace("https://", "hxxps://")
               .replace(".", "[.]"))


def shannon_entropy(text: str) -> float:
    if not text:
        return 0.0
    counts = Counter(text)
    total = len(text)
    return -sum((c / total) * math.log2(c / total) for c in counts.values())


def levenshtein(a: str, b: str) -> int:
    if a == b:
        return 0
    if len(a) < len(b):
        a, b = b, a
    previous = list(range(len(b) + 1))
    for i, ca in enumerate(a, 1):
        current = [i]
        for j, cb in enumerate(b, 1):
            current.append(min(previous[j] + 1, current[j - 1] + 1,
                               previous[j - 1] + (ca != cb)))
        previous = current
    return previous[-1]


def resolves_to_private(host: str) -> bool:
    """True if the host points at a private/loopback address.

    Used to stop the hosted app from probing internal networks (SSRF guard).
    """
    try:
        infos = socket.getaddrinfo(host, None)
    except socket.gaierror:
        return False
    for info in infos:
        ip = ipaddress.ip_address(info[4][0])
        if ip.is_private or ip.is_loopback or ip.is_link_local or ip.is_reserved:
            return True
    return False


def finding(check: str, detail: str, points: int, vector: str) -> dict:
    """Standard structure for one risk indicator."""
    if points >= 20:
        severity = "High"
    elif points >= 10:
        severity = "Medium"
    elif points > 0:
        severity = "Low"
    elif points < 0:
        severity = "Trust"
    else:
        severity = "Info"
    return {"vector": vector, "check": check, "detail": detail,
            "points": points, "severity": severity}
