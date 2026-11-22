"""Reference lists used by the lexical vector.

Kept in one file so they are easy to extend: add a brand, a hosting
platform or a lure word here and every check picks it up.
"""

# Brand keyword -> the real registered domains that brand uses.
# A brand name found anywhere else in a URL is treated as impersonation.
BRANDS = {
    # Global technology and social media
    "paypal": ["paypal.com", "paypal.me"],
    "google": ["google.com", "google.com.my", "youtube.com", "gmail.com"],
    "gmail": ["gmail.com", "google.com"],
    "apple": ["apple.com", "icloud.com"],
    "icloud": ["icloud.com", "apple.com"],
    "microsoft": ["microsoft.com", "microsoftonline.com", "live.com", "office.com", "outlook.com",
                  "office365.com", "sharepoint.com", "onedrive.com", "msn.com", "bing.com"],
    "microsoftonline": ["microsoftonline.com", "microsoft.com"],
    "office365": ["office365.com", "office.com", "microsoft.com", "microsoftonline.com"],
    "outlook": ["outlook.com", "office.com", "live.com", "microsoft.com", "office365.com"],
    "onedrive": ["onedrive.com", "live.com", "microsoft.com", "sharepoint.com"],
    "sharepoint": ["sharepoint.com", "microsoft.com"],
    "hotmail": ["hotmail.com", "live.com", "outlook.com"],
    "facebook": ["facebook.com", "fb.com", "meta.com"],
    "instagram": ["instagram.com"],
    "whatsapp": ["whatsapp.com", "whatsapp.net"],
    "telegram": ["telegram.org", "t.me"],
    "tiktok": ["tiktok.com"],
    "linkedin": ["linkedin.com"],
    "twitter": ["twitter.com", "x.com"],
    "discord": ["discord.com", "discord.gg", "discordapp.com"],
    "roblox": ["roblox.com"],
    "steam": ["steampowered.com", "steamcommunity.com"],
    "netflix": ["netflix.com"],
    "spotify": ["spotify.com"],
    "amazon": ["amazon.com", "amazon.co.uk", "amazon.de", "amazon.co.jp", "amazon.sg", "amazon.com.au"],
    "adobe": ["adobe.com"],
    "docusign": ["docusign.com", "docusign.net"],
    "dropbox": ["dropbox.com"],
    "wetransfer": ["wetransfer.com"],
    # Cryptocurrency
    "metamask": ["metamask.io"],
    "ledger": ["ledger.com"],
    "trustwallet": ["trustwallet.com"],
    "binance": ["binance.com"],
    "coinbase": ["coinbase.com"],
    "kraken": ["kraken.com"],
    "opensea": ["opensea.io"],
    "phantom": ["phantom.app", "phantom.com"],
    # Delivery
    "dhl": ["dhl.com", "dhl.com.my"],
    "fedex": ["fedex.com"],
    "usps": ["usps.com"],
    "ups": ["ups.com"],
    "poslaju": ["pos.com.my"],
    "jnt": ["jtexpress.my", "jet.co.id"],
    "ninjavan": ["ninjavan.co"],
    "gdex": ["gdexpress.com"],
    # Telecoms and banks (international)
    "xfinity": ["xfinity.com", "comcast.net"],
    "att": ["att.com", "att.net"],
    "verizon": ["verizon.com"],
    "chase": ["chase.com"],
    "wellsfargo": ["wellsfargo.com"],
    "bankofamerica": ["bankofamerica.com"],
    "hsbc": ["hsbc.com", "hsbc.com.my"],
    "citibank": ["citibank.com", "citi.com"],
    "dbs": ["dbs.com", "dbs.com.sg"],
    "ocbc": ["ocbc.com", "ocbc.com.my"],
    "uob": ["uob.com.sg", "uob.com.my"],
    # Malaysian banks
    "maybank": ["maybank2u.com.my", "maybank.com", "maybank.com.my"],
    "cimb": ["cimbclicks.com.my", "cimb.com", "cimb.com.my"],
    "publicbank": ["pbebank.com", "publicbank.com.my"],
    "pbebank": ["pbebank.com"],
    "rhb": ["rhbgroup.com", "rhbnow.com.my"],
    "hongleong": ["hlb.com.my", "hongleongconnect.my"],
    "hlb": ["hlb.com.my"],
    "bankislam": ["bankislam.com", "bankislam.biz"],
    "ambank": ["ambank.com.my", "ambankgroup.com"],
    "bsn": ["mybsn.com.my"],
    "affinbank": ["affinbank.com.my", "affinalways.com"],
    "alliancebank": ["alliancebank.com.my"],
    "bankrakyat": ["bankrakyat.com.my"],
    # Malaysian e-wallets, shopping, telcos and utilities
    "shopee": ["shopee.com.my", "shopee.com"],
    "lazada": ["lazada.com.my", "lazada.com"],
    "touchngo": ["touchngo.com.my", "tngdigital.com.my"],
    "tngdigital": ["tngdigital.com.my"],
    "boost": ["myboost.com.my"],
    "grab": ["grab.com"],
    "tnb": ["tnb.com.my", "mytnb.com.my"],
    "unifi": ["unifi.com.my"],
    "celcom": ["celcom.com.my", "celcomdigi.com"],
    "maxis": ["maxis.com.my"],
    "digi": ["digi.com.my", "celcomdigi.com"],
    # Malaysian government
    "lhdn": ["hasil.gov.my"],
    "hasil": ["hasil.gov.my"],
    "jpj": ["jpj.gov.my"],
    "myeg": ["myeg.com.my"],
    "pdrm": ["rmp.gov.my", "pdrm.gov.my"],
    "kwsp": ["kwsp.gov.my"],
    "epf": ["kwsp.gov.my"],
    "perkeso": ["perkeso.gov.my"],
    "socso": ["perkeso.gov.my"],
    "mysejahtera": ["malaysia.gov.my"],
    "bnm": ["bnm.gov.my"],
    "irs": ["irs.gov"],
}

# Brands that are short or are ordinary words ("att", "grab", "chase") only
# count when they appear as a whole word, e.g. att-mail-login, not "attack".
TOKEN_ONLY_BRANDS = {b for b in BRANDS if len(b) <= 4} | {
    "chase", "grab", "boost", "hasil", "steam", "phantom", "ledger", "kraken", "apple", "adobe"}

# Registered domains whose subdomains are websites made by anyone, for free.
# Real banks and companies do not run their login pages on these.
FREE_HOSTING = {
    "weebly.com", "weeblysite.com", "wixsite.com", "editorx.io", "vercel.app", "netlify.app",
    "pages.dev", "workers.dev", "r2.dev", "github.io", "gitlab.io", "firebaseapp.com", "web.app",
    "webflow.io", "godaddysites.com", "square.site", "blogspot.com", "wordpress.com", "glitch.me",
    "repl.co", "replit.app", "replit.dev", "herokuapp.com", "onrender.com", "000webhostapp.com",
    "ngrok.io", "ngrok.app", "ngrok-free.app", "trycloudflare.com", "azurewebsites.net",
    "gitbook.io", "notion.site", "canva.site", "framer.app", "framer.website", "carrd.co",
    "mystrikingly.com", "jimdosite.com", "site123.me", "yolasite.com", "myshopify.com",
    "surge.sh", "fly.dev", "railway.app", "appspot.com", "cloudfront.net", "amazonaws.com",
    "windows.net", "typedream.app", "mailchimpsites.com", "tilda.ws", "webnode.page",
    "pantheonsite.io", "translate.goog", "wixstudio.io", "softr.app", "bubbleapps.io",
    "glide.page", "durable.co", "hpage.com", "biz.id", "my.id", "web.id",
}

# IPFS gateways serve files that cannot be taken down; heavily used by phishing kits.
IPFS_HOSTS = {"ipfs.io", "dweb.link", "cloudflare-ipfs.com", "w3s.link", "nftstorage.link",
              "4everland.io", "fleek.co", "pinata.cloud"}

# Pages that anyone can create on an otherwise trusted domain (host, path prefix).
USER_CONTENT_PAGES = [
    ("sites.google.com", "/"), ("docs.google.com", "/forms"), ("docs.google.com", "/presentation"),
    ("docs.google.com", "/drawings"), ("script.google.com", "/"), ("storage.googleapis.com", "/"),
    ("firebasestorage.googleapis.com", "/"), ("forms.office.com", "/"), ("forms.gle", "/"),
    ("telegra.ph", "/"), ("linktr.ee", "/"), ("t.me", "/"),
]

# Words that phishing pages use to push victims into entering details.
# Includes Malay words used by local scams (saman, bayar, sahkan, ...).
CREDENTIAL_KEYWORDS = [
    "login", "logon", "signin", "sign-in", "signon", "sso", "auth", "verify", "verification",
    "validate", "validation", "account", "update", "secure", "security", "banking", "confirm",
    "password", "wallet", "suspend", "suspended", "locked", "unlock", "unusual", "expired",
    "billing", "invoice", "webscr", "authenticate", "authorize", "recover", "recovery", "restore",
    "reactivate", "support", "helpdesk", "webmail", "mfa", "2fa", "otp", "tac", "kyc", "seed",
    "phrase", "airdrop", "connect-wallet", "bonus", "gift", "nitro", "claim", "reward", "prize",
    "refund", "payment", "appeal", "copyright", "redelivery", "parcel",
    "sahkan", "pengesahan", "kemaskini", "akaun", "saman", "bayar", "bayaran", "pembayaran",
    "tuntut", "tuntutan", "semak", "hadiah", "bantuan",
]

SUSPICIOUS_TLDS = {
    "zip", "mov", "xyz", "top", "tk", "ml", "ga", "cf", "gq", "click", "country", "kim", "work",
    "rest", "fit", "icu", "buzz", "cam", "monster", "sbs", "cfd", "quest", "lol", "cyou", "bond",
    "online", "site", "cc", "live", "support", "help", "vip", "win", "shop", "pw", "su", "info",
    "today", "link", "lat",
}

URL_SHORTENERS = {
    "bit.ly", "tinyurl.com", "t.co", "goo.gl", "ow.ly", "is.gd", "buff.ly", "cutt.ly",
    "rebrand.ly", "shorturl.at", "rb.gy", "tiny.cc", "s.id", "lnkd.in", "t.ly", "v.gd",
    "qrco.de", "shorturl.asia", "urlis.net", "bitly.ws", "tinu.be",
}


def hosting_platform(host: str, reg_domain: str, path: str = "/"):
    """Return (kind, platform) if the URL is a page on a shared platform, else None."""
    for platform in IPFS_HOSTS:
        if host == platform or host.endswith("." + platform):
            return "ipfs", platform
    if "/ipfs/" in path.lower() or "/ipns/" in path.lower():
        return "ipfs", host
    for page_host, prefix in USER_CONTENT_PAGES:
        if host == page_host and path.lower().startswith(prefix):
            return "user_content", page_host
    for platform in FREE_HOSTING:
        if host != platform and host.endswith("." + platform):
            return "free_hosting", platform
    return None
