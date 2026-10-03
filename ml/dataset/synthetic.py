"""Synthetic labelled URL generator (bootstrap dataset).

WHY THIS EXISTS
    Real, labelled phishing/benign URL corpora are not redistributable and were
    not available offline when the project was scaffolded. This generator produces
    a reproducible bootstrap dataset so the whole pipeline (features -> training ->
    evaluation -> API) can run end to end.

WHAT IT IS *NOT*
    Metrics computed on this data measure how well the model learned the
    generator's patterns, not real-world phishing detection performance. The
    generator therefore builds in overlap on purpose (legitimate ``/login`` pages
    on brand domains, phishing on ordinary-looking compromised domains, shared
    hosting on both sides, "boring" phishing with no lexical signal) so the task is
    not trivially separable. Retrain on real data with
    ``python -m ml.dataset.build_dataset --mode files`` before drawing conclusions,
    and see ``ml/evaluation/external_check.py`` for an out-of-distribution check.
"""
from __future__ import annotations

import random
import string

import pandas as pd

from backend.services.reference_data import BRANDS, PHISHING_KEYWORDS

WORDS = (
    "alpha apex arbor atlas aurora beacon birch bloom bright canyon cedar cloud cobalt "
    "coral craft crest dawn delta drift eagle echo elm ember field flint forge frost "
    "garden glide grove harbor haven hill horizon indigo iron island jade juniper kite "
    "lake lantern leaf lime lumen maple meadow mesa mint moon mosaic nebula north nova "
    "oak ocean olive orbit otter pacific paper peak pine pixel planet plum prairie pulse "
    "quartz raven reef ridge river rock sage sand scout shore silver sky solar spark "
    "spruce stone summit sun swift tide timber trail tulip urban valley velvet violet "
    "vista wave willow wind winter wolf yard zenith news shop store media health learn "
    "travel finance sports music books tools design cloud data labs studio works group "
    "clinic market foods home garden auto pets kids tech digital global local city"
).split()

SUBDOMAINS_LEGIT = ["blog", "shop", "docs", "support", "mail", "api", "app", "news", "m", "en",
                    "store", "help", "cdn", "accounts", "secure", "login", "portal", "my", "dev"]
LEGIT_TLDS = (["com"] * 60 + ["org"] * 10 + ["net"] * 5 + ["co.uk"] * 3 + ["de"] * 3 + ["in"] * 3
              + ["io"] * 3 + ["edu"] * 3 + ["gov"] * 2 + ["com.bd"] * 2 + ["app"] * 2 + ["dev"] * 2
              + ["info"] * 1 + ["xyz"] * 1 + ["top"] * 1)
PHISH_TLDS = (["com"] * 30 + ["net"] * 6 + ["org"] * 4 + ["info"] * 5 + ["online"] * 6 + ["site"] * 5
              + ["store"] * 3 + ["top"] * 8 + ["xyz"] * 8 + ["icu"] * 4 + ["click"] * 3 + ["tk"] * 3
              + ["ml"] * 2 + ["ga"] * 2 + ["cf"] * 2 + ["gq"] * 2 + ["link"] * 2 + ["buzz"] * 2
              + ["cyou"] * 2 + ["sbs"] * 2 + ["shop"] * 2 + ["co"] * 1 + ["cc"] * 1 + ["me"] * 1)
SHARED = ["github.io", "blogspot.com", "weebly.com", "wixsite.com", "web.app", "firebaseapp.com",
          "pages.dev", "netlify.app", "vercel.app", "herokuapp.com", "glitch.me", "myshopify.com"]
BRAND_LIST = list(BRANDS)
KW = [k for k in PHISHING_KEYWORDS if "-" not in k]
UTM = ["utm_source", "utm_medium", "utm_campaign", "ref", "id", "page", "q", "lang", "sort", "tab"]


def _word(r): return r.choice(WORDS)
def _slug(r, lo=2, hi=6): return "-".join(r.choice(WORDS) for _ in range(r.randint(lo, hi)))
def _hex(r, n): return "".join(r.choice("0123456789abcdef") for _ in range(n))
def _rand(r, lo, hi): return "".join(r.choice(string.ascii_lowercase + string.digits) for _ in range(r.randint(lo, hi)))
def _ip(r): return ".".join(str(r.randint(11, 223)) for _ in range(4))
def _scheme(r, p_https): return "https" if r.random() < p_https else "http"


def _query(r, lo=0, hi=4):
    n = r.randint(lo, hi)
    return ("?" + "&".join(f"{r.choice(UTM)}={r.randint(1, 999)}" for _ in range(n))) if n else ""


# ---------------------------------------------------------------- domains
def legit_domain(r: random.Random) -> str:
    x = r.random()
    if x < 0.09:  # well-known brand's own domains
        b = r.choice(BRAND_LIST)
        return r.choice(BRANDS[b])
    if x < 0.22:  # personal/project sites on free hosting are common and legitimate
        return f"{_word(r)}{r.choice(['', '-', ''])}{r.choice([_word(r), _rand(r, 3, 6)])}.{r.choice(SHARED)}"
    tld = r.choice(LEGIT_TLDS)
    base = _word(r) + (_word(r) if r.random() < 0.5 else "")
    if r.random() < 0.10:
        base = _word(r) + "-" + _word(r)
    if r.random() < 0.05:
        base += str(r.randint(1, 99))
    return f"{base}.{tld}"


def legit_host(r: random.Random, dom: str) -> str:
    x = r.random()
    if x < 0.35:
        return dom
    if x < 0.75:
        return f"www.{dom}"
    if x < 0.97:
        return f"{r.choice(SUBDOMAINS_LEGIT)}.{dom}"
    return f"{_word(r)}.{r.choice(SUBDOMAINS_LEGIT)}.{dom}"


def legit_path(r: random.Random, brand_domain: bool) -> str:
    x = r.random()
    if brand_domain and x < 0.35:
        return r.choice(["/login", "/signin", "/account/settings", "/security", "/help/verify-identity",
                         "/signin/v2/identifier", "/gp/css/homepage.html", "/oauth2/authorize",
                         "/account/billing", "/wallet", "/payments/invoice/list",
                         "/security-center/overview/", "/help/security-and-fraud/",
                         "/personal/online-banking", "/us/webapps/mpp/security"]) + _query(r, 0, 3)
    if x < 0.17: return "/"
    if x < 0.23: return "/" + r.choice(["about", "contact", "pricing", "careers", "faq", "terms", "privacy", "privacy-policy"])
    if x < 0.31: return f"/products/{_slug(r, 1, 3)}-{r.randint(10, 99999)}"
    if x < 0.40: return f"/blog/{r.randint(2015, 2026)}/{r.randint(1, 12):02d}/{_slug(r, 3, 9)}" + _query(r, 0, 3)
    if x < 0.44: return f"/wiki/{_word(r).title()}" if r.random() < 0.8 else f"/wiki/{r.choice(BRAND_LIST).title()}"
    if x < 0.50: return f"/search{_query(r, 1, 3)}"
    if x < 0.56: return f"/{_word(r)}/{_word(r)}/{_slug(r, 1, 3)}"
    if x < 0.60: return f"/user/{r.randint(1, 99999)}/profile"
    # security/account vocabulary used innocently: docs, blogs, help centres, news
    if x < 0.70:
        return r.choice([
            f"/en-us/security/blog/{r.randint(2019, 2026)}/{r.randint(1, 12):02d}/{r.randint(1, 28):02d}/{_slug(r, 2, 5)}",
            f"/learning/security/what-is-{_word(r)}-{r.choice(['attack', 'authentication', 'verification', 'password'])}",
            f"/help/{r.choice(['account', 'security', 'billing', 'privacy', 'login'])}/{_slug(r, 2, 4)}",
            f"/blog/{r.randint(2018, 2026)}/{r.randint(1, 12):02d}/{r.randint(1, 28):02d}/{r.choice(['our-privacy-update', 'security-update-' + str(r.randint(2019, 2026)), 'how-to-secure-your-account', 'update-your-password-manager'])}/",
            f"/docs/{r.choice(['authentication', 'security', 'account-setup', 'verify-domain'])}/{_word(r)}",
            f"/account/{r.choice(['settings', 'orders', 'profile', 'billing'])}",
            f"/support/{_slug(r, 2, 5)}",
            f"/news/{r.randint(2019, 2026)}/{_slug(r, 4, 9)}-{r.choice(['security', 'account', 'password', 'phishing', 'banking'])}",
        ])
    if x < 0.76: return f"/{r.choice(['login', 'signin', 'account', 'secure/checkout', 'verify-email', 'password/reset', 'authenticate'])}"
    if x < 0.82: return f"/{_word(r)}.{r.choice(['html', 'php', 'aspx', 'htm'])}" + _query(r, 0, 2)
    if x < 0.87: return f"/{r.choice(['s', 'r', 'p', 'v', 'shared', 'share'])}/{_rand(r, 4, 10)}"
    if x < 0.91: return f"/{_word(r)}/{r.randint(1000, 99999999)}.html"
    return f"/static/{_word(r)}/{_hex(r, 8)}.{r.choice(['js', 'css', 'png', 'pdf'])}"


PLATFORM_LINKS = [
    lambda r: f"https://docs.google.com/forms/d/e/{_rand(r, 30, 45)}/viewform",
    lambda r: f"https://drive.google.com/file/d/{_rand(r, 25, 33)}/view",
    lambda r: f"https://sites.google.com/view/{_slug(r, 1, 3)}",
    lambda r: f"https://www.dropbox.com/s/{_rand(r, 12, 16)}/{_word(r)}.pdf",
    lambda r: f"https://{_word(r)}.sharepoint.com/:b:/s/{_word(r)}/{_rand(r, 30, 40)}",
    lambda r: f"https://forms.gle/{_rand(r, 10, 17)}",
    lambda r: f"https://www.canva.com/design/{_rand(r, 11, 11)}/view",
    lambda r: f"https://{_word(r)}.typeform.com/to/{_rand(r, 6, 8)}",
    lambda r: f"https://app.box.com/s/{_rand(r, 28, 32)}",
    lambda r: f"https://linktr.ee/{_word(r)}{r.randint(1, 99)}",
]


def gen_legit(r: random.Random, domain_pool: list[str]) -> str:
    x = r.random()
    if x < 0.015:
        return f"https://bit.ly/{_rand(r, 6, 7)}"
    if x < 0.02:
        return f"http://192.168.{r.randint(0, 5)}.{r.randint(2, 200)}:{r.choice([8080, 3000, 8000])}/{r.choice(['admin', 'dashboard', ''])}"
    if x < 0.07:
        return r.choice(PLATFORM_LINKS)(r)
    dom = r.choice(domain_pool)
    brand_domain = any(dom in v for v in BRANDS.values())
    host = legit_host(r, dom)
    return f"{_scheme(r, 0.9)}://{host}{legit_path(r, brand_domain)}"


# --------------------------------------------------------------- phishing
def _mutate(r: random.Random, brand: str) -> str:
    k = r.randint(0, 5)
    if k == 0:  # homoglyph
        for a, b in (("o", "0"), ("l", "1"), ("i", "1"), ("e", "3"), ("a", "4"), ("s", "5")):
            if a in brand and r.random() < 0.8:
                i = brand.rindex(a); return brand[:i] + b + brand[i + 1:]
    if k == 1 and len(brand) > 3:  # drop a char
        i = r.randrange(1, len(brand) - 1); return brand[:i] + brand[i + 1:]
    if k == 2 and len(brand) > 3:  # duplicate a char
        i = r.randrange(len(brand)); return brand[:i] + brand[i] + brand[i:]
    if k == 3 and len(brand) > 3:  # transpose
        i = r.randrange(len(brand) - 1); return brand[:i] + brand[i + 1] + brand[i] + brand[i + 2:]
    if k == 4 and "m" in brand:
        return brand.replace("m", "rn", 1)
    return brand.replace("l", "1", 1) if "l" in brand else brand + "s"


def _kwpath(r: random.Random) -> str:
    x = r.random()
    if x < 0.25: return f"/{r.choice(KW)}"
    if x < 0.5: return f"/{r.choice(KW)}/{r.choice(KW)}.{r.choice(['php', 'html'])}"
    if x < 0.7: return f"/{_word(r)}/{r.choice(KW)}-{r.choice(KW)}.php" + (f"?id={r.randint(1, 9999)}&session={_hex(r, 6)}" if r.random() < 0.5 else "")
    if x < 0.85: return "/"
    return f"/{_hex(r, r.randint(6, 16))}/{r.choice(KW)}"


def gen_phish(r: random.Random, evil_pool: list[str], shared_pool: list[str]) -> str:
    kind = r.choices(
        ["brand_sub", "typosquat", "brand_label", "ip", "shared", "compromised", "plain", "random",
         "mimic", "platform", "userinfo", "redirect", "punycode", "shortener", "boring", "exe"],
        [9, 8, 8, 6, 16, 10, 14, 7, 8, 4, 2, 2, 1, 3, 5, 2],
    )[0]
    tld = r.choice(PHISH_TLDS)
    b = r.choice(BRAND_LIST)
    sch = _scheme(r, 0.6)
    if kind == "brand_sub":
        shape = r.randint(0, 3)
        d = r.choice(evil_pool)
        host = [f"{b}.com.{r.choice(KW)}-{_word(r)}.{d}", f"{r.choice(KW)}.{b}.{d}",
                f"{b}-{r.choice(KW)}.{d}", f"{b}.{r.choice(KW)}.{_word(r)}.{d}"][shape]
        return f"{sch}://{host}{_kwpath(r)}"
    if kind == "typosquat":
        d = f"{_mutate(r, b)}.{tld}"
        return f"{sch}://{r.choice(['', 'www.', 'secure.'])}{d}{_kwpath(r)}"
    if kind == "brand_label":
        d = r.choice([f"{b}-{r.choice(KW)}", f"{r.choice(KW)}-{b}", f"{b}{r.choice(KW)}", f"{b}-{_word(r)}"])
        return f"{sch}://{d}.{tld}{_kwpath(r)}"
    if kind == "ip":
        host = _ip(r) if r.random() > 0.12 else str(r.randint(2 ** 24, 2 ** 32 - 1))
        port = r.choice(["", "", ":8080", ":8888", ":2083", ":81"])
        return f"http://{host}{port}{_kwpath(r) if r.random() < 0.7 else '/~' + _word(r) + '/' + r.choice(KW) + '.php'}"
    if kind == "shared":
        s = r.choice(shared_pool)
        label = r.choice([f"{b}-{r.choice(KW)}", f"{r.choice(KW)}{r.randint(1, 999)}", _slug(r, 1, 3),
                          f"{b}{_rand(r, 2, 5)}", _rand(r, 6, 12)])
        path = "/" if r.random() < 0.55 else r.choice([f"/{_word(r)}", f"/{_slug(r, 1, 2)}", _kwpath(r)])
        return f"https://{label}.{s}{path}"
    if kind == "compromised":
        d = r.choice(evil_pool)
        path = r.choice([
            f"/wp-content/plugins/{_word(r)}/{r.choice(KW)}/index.php",
            f"/wp-includes/{r.choice(KW)}/{_hex(r, 10)}/",
            f"/{r.choice(KW)}/{_hex(r, r.randint(8, 24))}/index.html",
            f"/modules/mod_{_word(r)}/{r.choice(KW)}.html",
            f"/images/{r.choice(KW)}/{r.choice(KW)}.php" + _query(r, 0, 2),
            f"/.well-known/{_hex(r, 6)}/{r.choice(KW)}.php",
            f"/{_word(r)}/{_word(r)}/{r.choice(KW)}",
        ])
        return f"{_scheme(r, 0.55)}://{r.choice(['', 'www.'])}{d}{path}"
    if kind == "plain":  # compromised/rented site, opaque path, no lexical give-aways
        d = r.choice(evil_pool)
        path = r.choice([f"/shared/{r.randint(1000, 99999)}.html", f"/s/{_rand(r, 4, 8)}", f"/l/{_rand(r, 5, 9)}",
                         f"/{_word(r)}/{r.randint(1000, 999999)}.html", "/pl", f"/{_word(r)}/{_word(r)}/{_rand(r, 5, 8)}",
                         f"/doc/{_hex(r, r.randint(8, 20))}", f"/view/{_rand(r, 6, 10)}.html", f"/{r.randint(10000, 9999999)}"])
        return f"{_scheme(r, 0.6)}://{r.choice(['', 'www.', 'app.'])}{d}{path}"
    if kind == "mimic":  # brand name on an odd country-code suffix, copying the real site's paths
        suffix = r.choice(["com.bi", "com.pt", "com.hr", "com.gr", "com.ro", "com.ng", "com.ly", "com.vc", "ac.ke",
                           "co.ve", "com.ec", "com.gt", "com.py", "com.bo", "cl", "ws", "ru.com", "us.com", "cc", "to"])
        path = legit_path(r, True) if r.random() < 0.6 else "/"
        return f"https://www.{b}.{suffix}{path}"
    if kind == "platform":
        return r.choice(PLATFORM_LINKS)(r)
    if kind == "random":
        return f"{sch}://{_rand(r, 8, 15)}.{r.choice(['top', 'xyz', 'icu', 'click', 'cyou', 'sbs', 'buzz', 'cfd'])}/{_rand(r, 3, 12)}"
    if kind == "userinfo":
        return f"http://{b}.com@{r.choice(evil_pool)}/{r.choice(KW)}"
    if kind == "redirect":
        return (f"{_scheme(r, 0.5)}://{r.choice(evil_pool)}/redirect.php?url=&u=&e=&"
                f"link=%2F%2F{_hex(r, 4)}%2F{r.choice(KW)}") if r.random() < 0.6 else \
               f"{_scheme(r, 0.5)}://{r.choice(evil_pool)}//{r.choice(KW)}//index.php"
    if kind == "punycode":
        return f"https://xn--{_rand(r, 5, 9)}-{_rand(r, 2, 3)}.{r.choice(['com', 'net', 'org', 'top'])}/{r.choice(KW)}"
    if kind == "shortener":
        return f"https://{r.choice(['bit.ly', 'tinyurl.com', 'cutt.ly', 'rb.gy', 'is.gd'])}/{_rand(r, 6, 7)}"
    if kind == "boring":
        return f"{_scheme(r, 0.7)}://{_word(r)}{_word(r)}.{r.choice(['com', 'net', 'org'])}/{_word(r)}"
    d = r.choice(evil_pool)  # exe
    return f"http://{d}/download/{_word(r)}.{r.choice(['exe', 'apk', 'zip', 'scr'])}"


def generate(n_per_class: int = 12000, seed: int = 1337) -> pd.DataFrame:
    r = random.Random(seed)
    legit_pool = [legit_domain(r) for _ in range(max(50, n_per_class // 5))]
    evil_pool = [f"{_word(r)}{r.choice(['', '-'])}{r.choice([_word(r), _rand(r, 3, 6)])}."
                 f"{r.choice(PHISH_TLDS if r.random() < 0.55 else LEGIT_TLDS)}"
                 for _ in range(max(50, n_per_class // 6))]
    shared_pool = SHARED
    rows = [(gen_legit(r, legit_pool), 0) for _ in range(n_per_class)]
    rows += [(gen_phish(r, evil_pool, shared_pool), 1) for _ in range(n_per_class)]
    df = pd.DataFrame(rows, columns=["url", "label"]).drop_duplicates("url")
    df["source"] = "synthetic-v2"
    return df.sample(frac=1.0, random_state=seed).reset_index(drop=True)
