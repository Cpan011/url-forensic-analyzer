"""Vector 1 - Lexical structural inspection.

Looks only at the text of the URL. No network access is needed, so this
vector always runs, even when WHOIS or the threat-intel API is unavailable.
"""

import re
from urllib.parse import urlparse, unquote

from .intel_lists import (BRANDS, CREDENTIAL_KEYWORDS, SUSPICIOUS_TLDS, TOKEN_ONLY_BRANDS,
                          URL_SHORTENERS, hosting_platform)
from .utils import (domain_label, finding, get_host, is_ip, levenshtein,
                    registered_domain, shannon_entropy)

SUSPICIOUS_KEYWORDS = CREDENTIAL_KEYWORDS
# Brands that legitimately own many country domains (google.co.uk, amazon.de, dhl.de ...)
GLOBAL_BRANDS = {"google", "amazon", "apple", "microsoft", "dhl", "fedex", "ups", "hsbc", "citibank",
                 "shopee", "lazada", "grab", "netflix", "spotify", "facebook", "paypal"}
CMS_FOLDERS = re.compile(r"/(wp-content|wp-includes|wp-admin|cgi-bin|\.well-known|vendor|images|uploads)/")
DECEPTIVE_PREFIX = re.compile(r"(?:^|[.-])([a-z0-9]+)\.(com|net|org|gov|edu)(?=[-.])")

VECTOR = "Lexical"

# File types that run code or hide code when downloaded (malware delivery).
RISKY_EXTENSIONS = {
    "exe", "scr", "msi", "bat", "cmd", "pif", "vbs", "vbe", "js", "jse", "wsf",
    "hta", "ps1", "jar", "dll", "apk", "xapk", "dmg", "pkg", "deb", "sh", "bin", "elf",
    "iso", "img", "vhd", "lnk", "zip", "rar", "7z", "gz", "tar", "cab",
    "docm", "xlsm", "pptm", "xlam",
}
DOUBLE_EXTENSION = re.compile(r"\.(pdf|doc|docx|xls|xlsx|jpg|jpeg|png|txt|mp3|mp4)\.(exe|scr|js|vbs|bat|cmd|hta|lnk)$")

# Words used by malware-download lures and botnet loaders.
MALWARE_KEYWORDS = [
    "download", "setup", "install", "installer", "crack", "cracked", "keygen", "patch",
    "activator", "serial", "warez", "torrent", "mod-apk", "modapk", "apk", "payload",
    "loader", "dropper", "mozi", "mirai", "bins", "update-flash", "flashplayer",
    "codec", "free-download",
]

# Characters attackers swap in to imitate a brand (paypa1, g00gle, rnicrosoft)
HOMOGLYPHS = {"0": "o", "1": "l", "3": "e", "4": "a", "5": "s", "7": "t",
              "8": "b", "@": "a", "$": "s"}


# Cyrillic/Greek letters that look identical to Latin ones in IDN attacks
CONFUSABLES = {"а": "a", "е": "e", "о": "o", "р": "p", "с": "c", "у": "y", "х": "x",
               "і": "i", "ј": "j", "ѕ": "s", "ԁ": "d", "һ": "h", "ӏ": "l", "ο": "o",
               "α": "a", "ν": "v", "ɡ": "g"}
VOWELS = set("aeiou")


def _unconfuse(text: str) -> str:
    text = "".join(CONFUSABLES.get(ch, ch) for ch in text)
    text = text.replace("rn", "m").replace("vv", "w")
    return "".join(HOMOGLYPHS.get(ch, ch) for ch in text)


def _decode_idn(host: str) -> str:
    labels = []
    for label in host.split("."):
        if label.startswith("xn--"):
            try:
                label = label.encode().decode("idna")
            except UnicodeError:
                pass
        labels.append(label)
    return ".".join(labels)


def _tokens(text: str) -> set:
    return {t for t in re.split(r"[^a-z0-9]+", text) if t}


def _brand_in(brand: str, text: str, tokens: set) -> bool:
    if brand in TOKEN_ONLY_BRANDS:
        return brand in tokens
    return brand in text


def _official_brand(reg_domain: str):
    for brand, official in BRANDS.items():
        if reg_domain in official:
            return brand
    return None


def _looks_generated(label: str) -> bool:
    """DGA heuristic: long, high entropy, and unpronounceable."""
    if "-" in label or len(label) < 10:
        return False
    letters = [c for c in label if c.isalpha()]
    if not letters:
        return False
    vowel_ratio = sum(c in VOWELS for c in letters) / len(letters)
    longest_consonant_run = max((len(m) for m in re.findall(r"[b-df-hj-np-tv-z]+", label)), default=0)
    return shannon_entropy(label) >= 3.3 and (vowel_ratio < 0.25 or longest_consonant_run >= 5)


def analyze(url: str, scheme_given: bool = True) -> dict:
    parsed = urlparse(url)
    host = get_host(url)
    reg_domain = registered_domain(host)
    label = domain_label(reg_domain)
    tld = host.rsplit(".", 1)[-1] if "." in host else ""
    subdomain = host[: -len(reg_domain)].rstrip(".") if reg_domain and host != reg_domain else ""
    path_query = (parsed.path or "") + ("?" + parsed.query if parsed.query else "")
    lowered = unquote(url).lower()
    unicode_host = _decode_idn(host)
    skeleton_host = _unconfuse(unicode_host)

    findings = []

    # Structural facts collected as evidence regardless of score.
    data = {
        "full_url": url,
        "scheme": parsed.scheme,
        "hostname": host,
        "registered_domain": reg_domain,
        "subdomain": subdomain or "(none)",
        "tld": tld,
        "port": parsed.port,
        "path": parsed.path or "/",
        "query": parsed.query or "(none)",
        "url_length": len(url),
        "hostname_length": len(host),
        "subdomain_levels": len(subdomain.split(".")) if subdomain else 0,
        "unicode_hostname": unicode_host if unicode_host != host else "(same)",
        "hyphens_in_domain": host.replace("xn--", "").count("-"),
        "digits_in_hostname": sum(c.isdigit() for c in host),
        "hostname_entropy": round(shannon_entropy(label), 3),
        "percent_encoded_chars": url.count("%"),
    }

    # --- Host-level checks -------------------------------------------------
    if is_ip(host):
        findings.append(finding("IP address used as host",
            f"The URL points to a raw IP ({host}) instead of a domain name.", 20, VECTOR))

    if "@" in parsed.netloc:
        findings.append(finding("'@' symbol in authority",
            "Browsers ignore everything before '@', which can hide the real destination.", 15, VECTOR))

    if "xn--" in host:
        findings.append(finding("Punycode (IDN) domain",
            f"Displays as '{unicode_host}'. Encoded international characters are a common homograph trick.", 15, VECTOR))

    if reg_domain in URL_SHORTENERS:
        findings.append(finding("URL shortener",
            f"{reg_domain} hides the final destination behind a redirect.", 15, VECTOR))

    if tld in SUSPICIOUS_TLDS:
        findings.append(finding("High-abuse top-level domain",
            f".{tld} is frequently abused for phishing and malware hosting.", 10, VECTOR))

    if data["subdomain_levels"] > 3:
        findings.append(finding("Excessive subdomains",
            f"{data['subdomain_levels']} subdomain levels can be used to bury the real domain.", 10, VECTOR))
    elif data["subdomain_levels"] == 3:
        findings.append(finding("Many subdomains",
            "3 subdomain levels detected.", 5, VECTOR))

    if data["hyphens_in_domain"] >= 2:
        findings.append(finding("Multiple hyphens in hostname",
            f"{data['hyphens_in_domain']} hyphens, typical of look-alike domains (secure-login-bank).", 5, VECTOR))

    if parsed.port and parsed.port not in (80, 443):
        findings.append(finding("Non-standard port",
            f"Port {parsed.port} is unusual for public websites.", 10, VECTOR))

    if not is_ip(host) and _looks_generated(label):
        findings.append(finding("High-randomness domain name",
            f"Entropy {data['hostname_entropy']} suggests an algorithmically generated (DGA) name.", 10, VECTOR))

    if not is_ip(host) and host and data["digits_in_hostname"] / len(host) > 0.3:
        findings.append(finding("Digit-heavy hostname",
            "More than 30% of the hostname is digits.", 5, VECTOR))

    # --- Shared hosting platforms --------------------------------------------
    platform = hosting_platform(host, reg_domain, parsed.path or "/")
    data["hosting_platform"] = f"{platform[1]} ({platform[0].replace('_', ' ')})" if platform else "(none)"
    if platform:
        kind, name = platform
        if kind == "ipfs":
            findings.append(finding("IPFS gateway",
                f"Served from IPFS via {name}. Pages on IPFS cannot be taken down and are widely used by "
                "phishing kits.", 30, VECTOR))
        elif kind == "free_hosting":
            findings.append(finding("Free hosting or website builder",
                f"The site is a page on {name}, where anyone can publish a website for free. "
                "Real banks and companies do not host their login pages there.", 15, VECTOR))
        else:
            findings.append(finding("User-made page on a trusted platform",
                f"Anyone can create pages on {name}; the trusted domain says nothing about who made this one.",
                10, VECTOR))

    # --- Brand impersonation and typosquatting ------------------------------
    official_brand = None if platform else _official_brand(reg_domain)
    host_tokens = _tokens(skeleton_host) | _tokens(host)
    rest = lowered.split(host, 1)[-1] if host in lowered else path_query.lower()
    rest_tokens = _tokens(rest)
    brand_hit = False
    data["impersonated_brand"] = "(none)"

    if official_brand:
        findings.append(finding("Known brand domain",
            f"{reg_domain} is an official {official_brand} domain.", -15, VECTOR))
        brand_hit = True
    elif not is_ip(host) or rest:
        in_host = [b for b in BRANDS if _brand_in(b, skeleton_host, host_tokens) or _brand_in(b, host, host_tokens)]
        in_rest = [b for b in BRANDS if _brand_in(b, rest, rest_tokens)]
        if in_host or in_rest:
            brand = max(in_host or in_rest, key=len)   # longest match: metamask beats meta
            where = "hostname" if in_host else "path/query"
            official = BRANDS[brand]
            data["impersonated_brand"] = brand
            findings.append(finding("Brand name outside its official domain",
                f"'{brand}' appears in the {where}, but the site is {platform[1] if platform else reg_domain}, "
                f"not {', '.join(official)}.", 25 if in_host else 15, VECTOR))
            brand_hit = True
            # roblox.com.ge copies roblox.com exactly, only the ending differs
            same_name = [d for d in official if domain_label(d) == label]
            if in_host and not platform and same_name and brand not in GLOBAL_BRANDS:
                findings.append(finding("Brand domain with a fake ending",
                    f"{reg_domain} copies the real {same_name[0]} but uses a different ending.", 15, VECTOR))
            if platform:
                findings.append(finding("Brand page on free hosting",
                    f"A '{brand}' page on a free/shared platform is almost never genuine.", 15, VECTOR))

    match = DECEPTIVE_PREFIX.search(host)
    if match and not official_brand:
        after = host[match.end():]
        if not re.fullmatch(r"\.[a-z]{2}", after):
            findings.append(finding("Deceptive domain prefix",
                f"'{match.group(1)}.{match.group(2)}' is placed at the start of the address, but the real "
                f"domain is {reg_domain}.", 20, VECTOR))

    skeleton_label = domain_label(registered_domain(skeleton_host))
    if not brand_hit and label and not is_ip(host) and not platform:
        for brand, official in BRANDS.items():
            official_labels = {domain_label(d) for d in official} | {brand}
            for target in official_labels:
                if len(target) < 5:
                    continue
                distance = levenshtein(skeleton_label, target)
                if (distance == 0 and skeleton_label != label) or 0 < distance <= 2:
                    shown = unicode_host if unicode_host != host else label
                    data["impersonated_brand"] = brand
                    findings.append(finding("Possible typosquatting",
                        f"'{shown}' is {distance} character(s) away from '{target}' ({brand}).", 30, VECTOR))
                    brand_hit = True
                    break
            if brand_hit:
                break

    # --- Path / query checks -------------------------------------------------
    found_keywords = sorted({k for k in SUSPICIOUS_KEYWORDS
                             if re.search(rf"(?<![a-z]){re.escape(k)}(?![a-z])", lowered)})
    data["suspicious_keywords"] = found_keywords or []
    if found_keywords:
        pts = min(5 * len(found_keywords), 20)
        findings.append(finding("Credential-lure keywords",
            f"Found: {', '.join(found_keywords)}.", pts, VECTOR))

    folder = CMS_FOLDERS.search((parsed.path or "").lower())
    path_keywords = [k for k in found_keywords if k in (parsed.path or "").lower()]
    if folder and not official_brand and (path_keywords or data["impersonated_brand"] != "(none)"):
        findings.append(finding("Login page in website system folder",
            f"A login or brand page sits inside /{folder.group(1)}/, a sign of a phishing kit uploaded "
            "to a hacked website.", 20, VECTOR))

    # --- Malware delivery checks -------------------------------------------
    last_segment = (parsed.path or "").rstrip("/").rsplit("/", 1)[-1].lower()
    extension = last_segment.rsplit(".", 1)[-1] if "." in last_segment else ""
    data["file_name"] = last_segment or "(none)"
    data["file_extension"] = extension or "(none)"
    if DOUBLE_EXTENSION.search(last_segment):
        findings.append(finding("Disguised executable (double extension)",
            f"'{last_segment}' pretends to be a document but is a program.", 30, VECTOR))
    elif extension in RISKY_EXTENSIONS:
        findings.append(finding("Executable or archive download",
            f"The link points directly to a .{extension} file, a common way to deliver malware.", 25, VECTOR))

    malware_words = sorted({k for k in MALWARE_KEYWORDS
                            if re.search(rf"(?<![a-z]){re.escape(k)}(?![a-z])", lowered)})
    data["malware_keywords"] = malware_words
    if malware_words:
        findings.append(finding("Malware-lure keywords",
            f"Found: {', '.join(malware_words)}.", min(5 * len(malware_words), 15), VECTOR))

    if "//" in path_query:
        findings.append(finding("Embedded redirect ('//' in path)",
            "A second '//' after the host can redirect to another site.", 10, VECTOR))

    if re.search(r"(https?|www)[^/]*[./]", path_query.lower()):
        findings.append(finding("URL embedded in path or query",
            "Another address appears inside the URL, often an open-redirect lure.", 5, VECTOR))

    if data["percent_encoded_chars"] > 5:
        findings.append(finding("Heavy percent-encoding",
            f"{data['percent_encoded_chars']} encoded characters may hide the real content.", 5, VECTOR))

    if len(url) > 120:
        findings.append(finding("Very long URL", f"{len(url)} characters.", 10, VECTOR))
    elif len(url) > 75:
        findings.append(finding("Long URL", f"{len(url)} characters.", 5, VECTOR))

    if parsed.scheme == "http" and scheme_given:
        findings.append(finding("Unencrypted HTTP",
            "The link uses plain HTTP, so anything typed into the page is sent unencrypted.", 10, VECTOR))
    elif not scheme_given:
        findings.append(finding("No scheme supplied",
            "No http:// or https:// was given, so http:// was assumed for parsing.", 0, VECTOR))

    return {"vector": VECTOR, "status": "ok", "data": data, "findings": findings}
