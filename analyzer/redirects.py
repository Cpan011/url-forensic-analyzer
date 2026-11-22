"""Short-link expansion.

Short links (bit.ly, tinyurl ...) hide where they lead. This module asks the
shortener for its redirect target by reading only the HTTP 'Location' header,
hop by hop. The destination page itself is never downloaded or rendered, so
the analysis stays passive and safe.
"""

from urllib.parse import urljoin

import requests

from .utils import get_host, resolves_to_private

MAX_HOPS = 5
TIMEOUT = 8
HEADERS = {"User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) URL-Forensic-Analyzer/1.0"}


def _next_hop(url: str):
    """Return the redirect target of url, or None if it does not redirect."""
    for method in ("HEAD", "GET"):
        resp = requests.request(method, url, headers=HEADERS, timeout=TIMEOUT,
                                allow_redirects=False, stream=True)
        resp.close()  # never read the body
        if resp.is_redirect or resp.status_code in (301, 302, 303, 307, 308):
            location = resp.headers.get("Location")
            return urljoin(url, location) if location else None
        if resp.status_code not in (403, 405, 501):
            return None
    return None


def expand(url: str) -> dict:
    chain = [url]
    try:
        while len(chain) <= MAX_HOPS:
            host = get_host(chain[-1])
            if not host or resolves_to_private(host):
                return {"chain": chain, "final_url": chain[-1],
                        "error": "Stopped: a hop points to a private or local address."}
            target = _next_hop(chain[-1])
            if not target or target in chain:
                break
            chain.append(target)
    except Exception as exc:
        if len(chain) > 1:  # destination found; it just could not be contacted for further hops
            return {"chain": chain, "final_url": chain[-1], "error": None}
        return {"chain": chain, "final_url": chain[-1],
                "error": f"The short-link service could not be reached ({type(exc).__name__})."}
    return {"chain": chain, "final_url": chain[-1], "error": None}
