"""Static reference data used by the feature engine and the risk engine.

These lists are deliberately small and transparent. They are heuristics, not
ground truth: the ML model learns how much weight each signal deserves, and the
lists can be extended without touching any code elsewhere.
"""
from __future__ import annotations

# brand keyword -> extra legitimate registered domains (in addition to
# "<brand>.<any non-risky, non-shared suffix>", which is accepted automatically).
BRANDS: dict[str, tuple[str, ...]] = {
    "paypal": ("paypal.com", "paypal.me", "paypalobjects.com"),
    "google": ("google.com", "googleapis.com", "gstatic.com", "googleusercontent.com",
               "youtube.com", "gmail.com", "goo.gl"),
    "microsoft": ("microsoft.com", "live.com", "office.com", "microsoftonline.com",
                  "outlook.com", "windows.com", "azure.com", "bing.com", "msn.com",
                  "sharepoint.com", "onedrive.com", "skype.com", "office365.com"),
    "apple": ("apple.com", "icloud.com"),
    "amazon": ("amazon.com", "amazon.co.uk", "amazon.de", "amazon.in", "amazon.co.jp"),
    "facebook": ("facebook.com", "fb.com", "messenger.com"),
    "instagram": ("instagram.com",),
    "whatsapp": ("whatsapp.com", "whatsapp.net"),
    "netflix": ("netflix.com", "nflxso.net"),
    "linkedin": ("linkedin.com",),
    "twitter": ("twitter.com", "x.com", "t.co"),
    "dropbox": ("dropbox.com", "dropboxusercontent.com"),
    "docusign": ("docusign.com", "docusign.net"),
    "adobe": ("adobe.com",),
    "ebay": ("ebay.com", "ebay.co.uk", "ebay.de"),
    "chase": ("chase.com",),
    "wellsfargo": ("wellsfargo.com",),
    "bankofamerica": ("bankofamerica.com",),
    "citibank": ("citibank.com", "citi.com"),
    "hsbc": ("hsbc.com", "hsbc.co.uk"),
    "barclays": ("barclays.com", "barclays.co.uk"),
    "santander": ("santander.com", "santander.co.uk"),
    "americanexpress": ("americanexpress.com",),
    "coinbase": ("coinbase.com",),
    "binance": ("binance.com",),
    "metamask": ("metamask.io",),
    "blockchain": ("blockchain.com",),
    "steam": ("steampowered.com", "steamcommunity.com"),
    "discord": ("discord.com", "discordapp.com", "discord.gg"),
    "spotify": ("spotify.com",),
    "zoom": ("zoom.us",),
    "github": ("github.com", "githubusercontent.com"),
    "yahoo": ("yahoo.com",),
    "icloud": ("icloud.com",),
    "outlook": ("outlook.com", "office.com", "live.com"),
    "office365": ("office.com", "office365.com", "microsoft.com"),
    "fedex": ("fedex.com",),
    "usps": ("usps.com",),
    "dhl": ("dhl.com", "dhl.de"),
    "bkash": ("bkash.com",),
    "nagad": ("nagad.com.bd",),
    "daraz": ("daraz.com.bd", "daraz.pk", "daraz.lk"),
    "roblox": ("roblox.com",),
    "tiktok": ("tiktok.com",),
    "snapchat": ("snapchat.com",),
    "pinterest": ("pinterest.com",),
    "wetransfer": ("wetransfer.com",),
    "godaddy": ("godaddy.com",),
    "telegram": ("telegram.org", "t.me"),
    "epicgames": ("epicgames.com",),
    "playstation": ("playstation.com",),
    "xbox": ("xbox.com",),
    "ledger": ("ledger.com",),
    "trustwallet": ("trustwallet.com",),
    "opensea": ("opensea.io",),
    "kraken": ("kraken.com",),
    "uniswap": ("uniswap.org",),
    "verizon": ("verizon.com",),
    "aliexpress": ("aliexpress.com",),
    "paytm": ("paytm.com",),
}

# Suffixes under which a brand's own label is accepted as genuine ("amazon.co.uk",
# "google.de"). Anything else -- e.g. "roblox.com.bi" or "paypal.tk" -- is treated as a
# look-alike. Extend as needed; the cost of a miss is one extra weak indicator.
TRUSTED_BRAND_SUFFIXES: frozenset[str] = frozenset({
    "com", "net", "org", "io", "co", "us", "uk", "co.uk", "de", "fr", "it", "es", "nl", "se",
    "ca", "in", "co.in", "com.au", "au", "jp", "co.jp", "com.br", "br", "mx", "com.mx", "ru",
    "cn", "com.cn", "kr", "co.kr", "eu", "ch", "at", "be", "pl", "ie", "ae", "sg", "com.sg",
    "nz", "co.nz", "za", "co.za", "tr", "com.tr", "bd", "com.bd", "pk", "com.pk", "lk", "ph",
    "com.ph", "id", "co.id", "vn", "com.vn", "th", "co.th", "my", "com.my",
})

# Tokens are matched loosely inside URL components; see features._brand_hits.
PHISHING_KEYWORDS: tuple[str, ...] = (
    "login", "signin", "sign-in", "logon", "verify", "verification", "secure",
    "security", "account", "update", "confirm", "banking", "password", "passwd",
    "credential", "wallet", "suspend", "unlock", "billing", "invoice", "payment",
    "recover", "webscr", "authenticate", "validate", "alert", "expire", "restore",
)

# TLDs disproportionately abused for throw-away domains. Heuristic only: many
# legitimate sites use these too, so the ML model and risk engine keep the weight low.
RISKY_TLDS: frozenset[str] = frozenset({
    "zip", "mov", "top", "xyz", "tk", "ml", "ga", "cf", "gq", "click", "link", "work",
    "support", "country", "kim", "loan", "men", "review", "stream", "download",
    "racing", "science", "party", "date", "faith", "accountant", "cricket", "buzz",
    "icu", "cyou", "rest", "monster", "cam", "sbs", "bond", "cfd",
})

URL_SHORTENERS: frozenset[str] = frozenset({
    "bit.ly", "tinyurl.com", "t.co", "goo.gl", "ow.ly", "is.gd", "buff.ly",
    "rebrand.ly", "cutt.ly", "shorturl.at", "tiny.cc", "rb.gy", "lnkd.in", "s.id",
})

# Public-suffix-style hosts where anyone can publish under a subdomain. A brand name
# under these is never the brand's own site.
SHARED_HOSTING_SUFFIXES: frozenset[str] = frozenset({
    "github.io", "gitlab.io", "blogspot.com", "weebly.com", "wixsite.com", "web.app",
    "firebaseapp.com", "pages.dev", "workers.dev", "netlify.app", "vercel.app",
    "herokuapp.com", "glitch.me", "appspot.com", "azurewebsites.net", "amplifyapp.com",
    "myshopify.com", "wordpress.com", "sites.google.com", "notion.site", "carrd.co",
    "webflow.io", "repl.co", "replit.app", "onrender.com", "fly.dev", "surge.sh",
    "s3.amazonaws.com", "cloudfront.net", "ngrok.io", "ngrok-free.app", "trycloudflare.com",
    "r2.dev", "framer.website", "000webhostapp.com", "weeblysite.com", "godaddysites.com",
})

# Very large multi-tenant platforms. A single reported URL on these hosts must never
# make the whole host look malicious (host-level threat-intel matches are disabled).
LARGE_PLATFORM_DOMAINS: frozenset[str] = frozenset({
    "google.com", "docs.google.com", "forms.gle", "microsoft.com", "sharepoint.com",
    "dropbox.com", "github.com", "githubusercontent.com", "amazonaws.com", "notion.so",
    "facebook.com", "medium.com", "youtube.com", "linkedin.com", "twitter.com", "x.com",
    "cloudflare.com", "wordpress.org", "wikipedia.org", "office.com", "live.com",
})

EXECUTABLE_EXTENSIONS: tuple[str, ...] = (
    ".exe", ".apk", ".scr", ".bat", ".msi", ".jar", ".iso", ".dmg", ".vbs", ".ps1",
    ".zip", ".rar",
)

HOMOGLYPHS = str.maketrans({"0": "o", "1": "l", "3": "e", "4": "a", "5": "s", "$": "s", "@": "a"})
