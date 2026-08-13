"""
TrustScan — site trust scoring for ProductFilter.

A faithful Python port of the TrustScan AI engine (originally lib/score.js +
app/api/score/route.js in the Next.js build). Runs in-process inside Flask so
there is no second service to deploy and no network hop per search.

Scoring
-------
Every URL starts at 100 and loses points for each risk signal found in the
address itself (transport, URL structure, phishing keywords, brand
impersonation). Optional live feeds can push the score down further:

    OpenPhish        community phishing feed, no key, cached 10 min
    Safe Browsing    Google Safe Browsing v4, optional free key, batched
    RDAP + DNS       domain age / resolvability, deep mode only, cached 24h

Final score is 0-97, higher = safer. A "critical" finding caps the score at
38; a confirmed blocklist hit caps it at 15.

Everything degrades gracefully: with no keys and no network the heuristic
engine alone still scores every URL.

Public API
----------
    score_url(url, deep=False)            -> dict
    score_urls([url, ...], deep=False)    -> {url: dict}
    is_trusted(result, minimum=50)        -> bool
"""

import os
import re
import json
import time
import math
import threading
from urllib.parse import urlparse, urlsplit, unquote, quote

try:
    import requests
except ImportError:  # pragma: no cover - requests is in requirements.txt
    requests = None


# ---------------------------------------------------------------------------
# Tables (kept identical to the JS engine)
# ---------------------------------------------------------------------------

BRANDS = [
    "google", "gmail", "youtube", "facebook", "instagram", "whatsapp", "telegram",
    "twitter", "tiktok", "linkedin", "snapchat", "amazon", "apple", "icloud",
    "microsoft", "outlook", "netflix", "spotify", "paypal", "venmo", "zelle",
    "stripe", "visa", "mastercard", "coinbase", "binance", "kraken", "metamask",
    "chase", "wellsfargo", "citibank", "hsbc", "barclays", "santander", "dropbox",
    "adobe", "steam", "epicgames", "roblox", "ebay", "walmart", "bestbuy",
    "costco", "usps", "fedex", "github", "gitlab", "discord", "reddit", "twitch",
    "amex", "americanexpress", "fidelity", "schwab", "robinhood", "shopify",
    "alibaba", "aliexpress", "samsung", "verizon", "xfinity", "tmobile",
    "vodafone", "airbnb", "booking", "expedia", "uber", "docusign",
    # Indian retail brands ProductFilter actually deals with
    "flipkart", "myntra", "snapdeal", "paytm", "phonepe", "jiomart", "bigbasket",
    "reliance", "croma", "tatacliq", "ajio", "nykaa", "meesho", "pharmeasy",
    "netmeds", "1mg", "apollopharmacy", "zepto", "blinkit", "swiggy", "zomato",
    "irctc", "sbi", "hdfc", "icici", "axisbank", "kotak",
]

HIGH_RISK_TLDS = [
    "tk", "ml", "ga", "cf", "gq", "zip", "mov", "stream", "download", "racing",
    "accountant", "loan", "win", "bid", "men", "gdn", "country",
]

# Free-to-register throwaway TLDs (the old Freenom set). A real shop that wants
# your card details does not trade on a domain that costs nothing and can be
# abandoned without loss, so for a shopping context these are disqualifying
# rather than merely suspicious.
FREE_TLDS = ["tk", "ml", "ga", "cf", "gq"]

MED_RISK_TLDS = [
    "xyz", "top", "icu", "click", "link", "work", "rest", "buzz", "monster",
    "cyou", "cam", "quest", "sbs", "pw", "cc", "best", "bond", "beauty",
]

SHORTENERS = [
    "bit.ly", "tinyurl.com", "t.co", "goo.gl", "is.gd", "buff.ly", "ow.ly",
    "cutt.ly", "rb.gy", "shorturl.at", "tiny.cc", "rebrand.ly", "s.id", "v.gd",
    "lnkd.in", "t.ly", "shorte.st", "adf.ly",
]

PHISH_WORDS = [
    "login", "log-in", "signin", "sign-in", "verify", "verification", "secure",
    "security", "account", "update", "confirm", "banking", "wallet", "password",
    "credential", "recover", "unlock", "suspended", "invoice", "payment",
    "billing", "refund", "gift", "bonus", "free", "prize", "winner", "urgent",
    "alert", "support", "helpdesk", "webmail", "authenticate", "2fa", "otp",
    "claim", "reward", "promo", "airdrop",
]

MULTI_TLDS = [
    "co.uk", "org.uk", "ac.uk", "gov.uk", "com.au", "net.au", "org.au", "co.nz",
    "co.jp", "ne.jp", "co.in", "co.kr", "com.br", "com.mx", "com.ar", "co.za",
    "com.sg", "com.my", "com.tr", "com.cn", "com.hk", "com.tw", "org.in",
    "net.in", "gov.in", "ac.in",
]

LEET = {
    "0": "o", "1": "l", "3": "e", "4": "a", "5": "s", "6": "b",
    "7": "t", "8": "b", "9": "g", "@": "a", "$": "s",
}

# Retailers ProductFilter already trusts. These are verified marketplaces; a bare
# heuristic pass on a deep affiliate URL shouldn't be able to knock them out of
# the results, so a match here sets a score floor.
KNOWN_GOOD_DOMAINS = {
    "amazon.in", "amazon.com", "flipkart.com", "croma.com", "tatacliq.com",
    "reliancedigital.in", "vijaysales.com", "myntra.com", "ajio.com",
    "nykaa.com", "snapdeal.com", "shopclues.com", "paytmmall.com",
    "jiomart.com", "bigbasket.com", "blinkit.com", "zeptonow.com",
    "dmart.in", "spencers.in", "licious.in", "meesho.com",
    "pharmeasy.in", "netmeds.com", "1mg.com", "tatadigital.com",
    "apollopharmacy.in", "truemeds.in", "medplusmart.com", "wellnessforever.in",
    "apple.com", "samsung.com", "mi.com", "oneplus.in", "realme.com",
    "oppo.com", "vivo.com", "nothing.tech", "motorola.in", "asus.com",
    "lenovo.com", "hp.com", "dell.com", "acer.com", "msi.com",
    "google.com", "sangeethamobiles.com", "poorvikamobile.com",
    "imagine.co.in", "unicornstore.in", "bajajelectronics.com",
}
KNOWN_GOOD_FLOOR = 82

# A domain nobody recognises cannot score in the "verified retailer" band. The
# heuristics can only prove the ABSENCE of bad signals — never the presence of
# a real business — so a clean unknown shop tops out just below the green band
# and is shown with an amber badge instead. Domain age (deep mode) can lift it.
UNKNOWN_CAP = int(os.getenv("TRUSTSCAN_UNKNOWN_CAP", "79"))

# Store names (SerpApi "source" field) mapped to their real domain. SerpApi
# often hands back a google.com/shopping redirect instead of the merchant URL,
# which would otherwise score the wrong domain entirely.
STORE_DOMAIN_HINTS = {
    "amazon": "amazon.in",
    "amazon.in": "amazon.in",
    "flipkart": "flipkart.com",
    "croma": "croma.com",
    "tata cliq": "tatacliq.com",
    "tatacliq": "tatacliq.com",
    "reliance digital": "reliancedigital.in",
    "vijay sales": "vijaysales.com",
    "myntra": "myntra.com",
    "ajio": "ajio.com",
    "nykaa": "nykaa.com",
    "snapdeal": "snapdeal.com",
    "jiomart": "jiomart.com",
    "bigbasket": "bigbasket.com",
    "blinkit": "blinkit.com",
    "zepto": "zeptonow.com",
    "dmart": "dmart.in",
    "meesho": "meesho.com",
    "pharmeasy": "pharmeasy.in",
    "netmeds": "netmeds.com",
    "tata 1mg": "1mg.com",
    "1mg": "1mg.com",
    "apollo pharmacy": "apollopharmacy.in",
    "apple": "apple.com",
    "samsung": "samsung.com",
    "sangeetha mobiles": "sangeethamobiles.com",
    "poorvika": "poorvikamobile.com",
}

# Hosts that are search/redirect surfaces rather than merchants. When we see
# one we fall back to scoring the store name instead of the URL.
REDIRECT_HOSTS = (
    "google.com", "google.co.in", "googleadservices.com", "shopping.google.com",
    "bing.com", "duckduckgo.com",
)

# Softens the plain-HTTP rule from critical back to a simple deduction.
ALLOW_HTTP = os.getenv("TRUSTSCAN_ALLOW_HTTP", "0") in ("1", "true", "True")

CRITICAL_CAP = 38
LISTED_CAP = 15
MAX_SCORE = 97


def clamp(n, lo, hi):
    return max(lo, min(hi, n))


def risk_of(score):
    if score >= 80:
        return "Low"
    if score >= 60:
        return "Moderate"
    if score >= 40:
        return "Elevated"
    if score >= 20:
        return "High"
    return "Critical"


def badge_of(score):
    """Colour token the templates use for the trust chip."""
    if score >= 80:
        return "safe"
    if score >= 65:
        return "ok"
    if score > 50:
        return "watch"
    return "risk"


def _lev(a, b, max_d=None):
    """Levenshtein distance, iterative two-row form.

    `max_d` is a cheap early exit: every caller here only cares whether the
    distance is within a small typo window, and the length difference is a
    lower bound on the distance. Without it, a 1500-character domain label was
    run through the full O(len(a) x len(b)) matrix against ~100 brands — about
    0.7s of CPU for a single request, 550x a normal scan, which at 50 requests
    per minute per IP is an easy one-machine denial of service.
    """
    if a == b:
        return 0
    m, n = len(a), len(b)
    if not m:
        return n
    if not n:
        return m
    if max_d is not None and abs(m - n) > max_d:
        return max_d + 1
    prev = list(range(n + 1))
    for i in range(1, m + 1):
        cur = [i] + [0] * n
        for j in range(1, n + 1):
            cur[j] = min(
                prev[j] + 1,
                cur[j - 1] + 1,
                prev[j - 1] + (0 if a[i - 1] == b[j - 1] else 1),
            )
        prev = cur
    return prev[n]


def _deleet(s):
    out = "".join(LEET.get(c, c) for c in s)
    return out.replace("rn", "m").replace("vv", "w")


def split_host(host):
    parts = [p for p in host.lower().split(".") if p]
    if len(parts) < 2:
        return {"sld": host, "tld": "", "sub": [], "registrable": host}
    tld = parts[-1]
    sld_index = len(parts) - 2
    last_two = ".".join(parts[-2:])
    if last_two in MULTI_TLDS and len(parts) >= 3:
        tld = last_two
        sld_index = len(parts) - 3
    sld = parts[sld_index]
    return {
        "sld": sld,
        "tld": tld,
        "sub": parts[:sld_index],
        "registrable": sld + "." + tld,
    }


IP_RE = re.compile(r"^\d{1,3}(\.\d{1,3}){3}$")
SCHEME_RE = re.compile(r"^[a-zA-Z][a-zA-Z0-9+.-]*://")


def parse_input(raw):
    """Normalise user/SerpApi input into a parsed URL, or explain why not.

    Accepts anything at all: SerpApi has been seen returning ints, None and
    nested objects in the link field, and a scorer that raises on bad input is
    a scorer that fails open.
    """
    if raw is None:
        raw = ""
    elif not isinstance(raw, str):
        try:
            raw = str(raw)
        except Exception:
            return {"valid": False, "error": "Unreadable URL value."}
    raw = raw.strip()
    if not raw:
        return {"valid": False, "error": "Empty URL."}
    if len(raw) > 2048:
        return {"valid": False, "error": "URL longer than 2048 characters."}
    if re.search(r"\s", raw):
        return {"valid": False, "error": "URLs cannot contain spaces."}

    had_scheme = bool(SCHEME_RE.match(raw))
    candidate = raw if had_scheme else "https://" + raw
    try:
        u = urlsplit(candidate)
    except ValueError:
        return {"valid": False, "error": "Does not parse as a URL."}

    if u.scheme not in ("http", "https"):
        return {"valid": False, "error": "Only http(s) addresses are supported."}
    if not u.hostname or ("." not in u.hostname and u.hostname != "localhost"):
        return {"valid": False, "error": "Hostname looks incomplete."}

    # DNS limits, enforced at the door: 253 characters total, 63 per label.
    # Nothing longer can resolve, so accepting it only ever fed oversized
    # strings into the per-brand similarity checks below.
    host_l = u.hostname.lower()
    if len(host_l) > 253:
        return {"valid": False, "error": "Hostname longer than 253 characters."}
    if any(len(lbl) > 63 for lbl in host_l.split(".")):
        return {"valid": False, "error": "Hostname label longer than 63 characters."}

    try:
        u.port  # raises ValueError on a malformed port such as ":alert(1)"
    except ValueError:
        return {"valid": False, "error": "Invalid port in URL."}

    return {
        "valid": True,
        "url": u,
        "href": candidate,
        "had_scheme": had_scheme,
        "raw": raw,
    }


# ---------------------------------------------------------------------------
# Heuristic engine
# ---------------------------------------------------------------------------

def analyze(parsed):
    """Score signals readable from the address alone. No network calls."""
    u = parsed["url"]
    host = (u.hostname or "").lower()
    findings = []

    def add(**f):
        f.setdefault("delta", 0)
        f.setdefault("critical", False)
        findings.append(f)

    is_ip = bool(IP_RE.match(host)) or host.startswith("[")
    hp = ({"sld": host, "tld": "", "sub": [], "registrable": host}
          if is_ip else split_host(host))
    sld, tld, sub, registrable = hp["sld"], hp["tld"], hp["sub"], hp["registrable"]
    sub_no_www = [s for s in sub if s != "www"]
    path_q = (u.path + ("?" + u.query if u.query else "")).lower()

    # ---- Transport -------------------------------------------------------
    if u.scheme == "https":
        add(id="scheme", category="Transport", status="pass",
            title="HTTPS" if parsed["had_scheme"] else "HTTPS assumed",
            detail="Traffic to this address is encrypted with TLS.")
    else:
        # A price comparison sends people somewhere to *pay*. Plain HTTP means
        # card details and session cookies cross the network in the clear and
        # the page can be rewritten in transit, so this is critical here rather
        # than the generic engine's -12. Set TRUSTSCAN_ALLOW_HTTP=1 to soften
        # it back to a deduction if you need to list http-only shops.
        add(id="scheme", category="Transport", status="fail", delta=-12,
            critical=not ALLOW_HTTP,
            title="Plain HTTP — no encryption",
            detail="Payment details on this address would travel unencrypted "
                   "and the page can be modified in transit.")

    # ---- URL structure ---------------------------------------------------
    struct_flags = 0

    if u.username or u.password:
        # "https://user:pass@evil.tk@amazon.in/" ends at a real hostname, so
        # every brand and reputation check passes — which is exactly why this
        # shape is used. No genuine retailer link carries userinfo, so it is
        # critical rather than a -15 nudge.
        struct_flags += 1
        add(id="userinfo", category="URL structure", status="fail", delta=-15, critical=True,
            title="Credentials embedded before an @ sign",
            detail="Everything before the @ is a decoy — the browser connects to " + host + ".")

    if u.port and u.port not in (80, 443):
        struct_flags += 1
        add(id="port", category="URL structure", status="warn", delta=-6,
            title="Non-standard port :%s" % u.port,
            detail="Ordinary shops serve on 80/443.")

    if is_ip:
        # Deviation from the generic TrustScan engine: in a shopping context a
        # bare IP is never a real storefront, so this is treated as critical
        # (score capped at 38) rather than a -15 nudge.
        struct_flags += 1
        add(id="ip", category="URL structure", status="fail", delta=-15, critical=True,
            title="Raw IP address instead of a domain",
            detail="Legitimate retailers link to a named domain, never a bare IP.")

    if "%" in host:
        # A real hostname never contains a percent sign. Encoding one hides
        # look-alike characters from every string check below it
        # ("ama%7Azon.in" defeats a plain comparison against "amazon").
        struct_flags += 1
        add(id="pcthost", category="URL structure", status="fail", delta=-25, critical=True,
            title="Percent-encoded characters in the hostname",
            detail="Encoding inside the host is used to smuggle look-alike characters past filters.")

    if "xn--" in host or any(ord(c) > 127 for c in host):
        struct_flags += 1
        add(id="puny", category="URL structure", status="fail", delta=-25, critical=True,
            title="Punycode / internationalized hostname",
            detail="Non-ASCII lookalike characters are the standard vehicle for impersonation.")

    if not is_ip and len(sub_no_www) >= 3:
        struct_flags += 1
        add(id="subdepth", category="URL structure", status="fail", delta=-10,
            title="%d chained subdomains" % len(sub_no_www),
            detail="The real owner (%s) hides at the end of the chain." % registrable)
    elif not is_ip and len(sub_no_www) == 2:
        struct_flags += 1
        add(id="subdepth", category="URL structure", status="warn", delta=-4,
            title="Multiple subdomains",
            detail="The registered owner of this page is %s." % registrable)

    if registrable in SHORTENERS:
        # Deviation from the generic engine: a price comparison result should
        # always name its merchant. A shortener hides who is actually being
        # paid, so it is critical here rather than a -10 warning.
        struct_flags += 1
        add(id="short", category="URL structure", status="fail", delta=-10, critical=True,
            title="Link shortener — merchant hidden",
            detail="The real destination sits behind %s and cannot be verified." % registrable)

    query_l = (u.query or "").lower()
    if re.search(r"(^|&)[^=]*=https?(:|%3a)", query_l) or "http%3a" in path_q or "https%3a" in path_q:
        struct_flags += 1
        add(id="redir", category="URL structure", status="warn", delta=-8,
            title="Embedded URL in the query string",
            detail="A second address is packed inside this one — an open-redirect shape.")

    if len(parsed["raw"]) > 120:
        struct_flags += 1
        add(id="len", category="URL structure", status="warn", delta=-4,
            title="Unusually long URL (%d chars)" % len(parsed["raw"]),
            detail="Length pushes the real destination out of sight on mobile.")

    if not is_ip and sld.count("-") >= 3:
        struct_flags += 1
        add(id="hyphens", category="URL structure", status="warn", delta=-5,
            title="Hyphen-stuffed domain label",
            detail='"%s" — multi-hyphen labels are common in scam registrations.' % sld)

    if struct_flags == 0:
        add(id="struct-ok", category="URL structure", status="pass",
            title="Clean structure — no obfuscation patterns",
            detail="No embedded credentials, IP literals, deep chains or hidden redirects.")

    # ---- Phishing heuristics --------------------------------------------
    if not is_ip and tld:
        bare_tld = tld.split(".")[-1]
        if bare_tld in FREE_TLDS:
            add(id="tld", category="Phishing heuristics", status="fail", delta=-25, critical=True,
                title='".%s" is a free throwaway domain' % tld,
                detail="Domains on this extension cost nothing and are abandoned freely. "
                       "No established retailer sells on one.")
        elif bare_tld in HIGH_RISK_TLDS:
            add(id="tld", category="Phishing heuristics", status="fail", delta=-12,
                title='".%s" is a heavily abused TLD' % tld,
                detail="This extension appears in scam campaigns far above baseline rates.")
        elif bare_tld in MED_RISK_TLDS:
            add(id="tld", category="Phishing heuristics", status="warn", delta=-6,
                title='".%s" has an elevated abuse rate' % tld,
                detail="Cheap, loosely policed extensions attract disposable scam shops.")
        else:
            add(id="tld", category="Phishing heuristics", status="pass",
                title='No elevated abuse rate for ".%s"' % tld,
                detail="This extension is not on the high-abuse lists tracked here.")

    host_hits = [w for w in PHISH_WORDS if w in host]
    path_hits = [w for w in PHISH_WORDS if w in path_q]

    if host_hits:
        add(id="kw-host", category="Phishing heuristics",
            status="fail" if len(host_hits) > 1 else "warn",
            delta=-min(12, 5 * len(host_hits)),
            title="Bait keywords inside the hostname",
            detail='Found: "%s".' % '", "'.join(host_hits[:5]))
    elif len(path_hits) >= 2:
        add(id="kw-path", category="Phishing heuristics", status="warn", delta=-4,
            title="Multiple bait keywords in the path",
            detail='Found: "%s".' % '", "'.join(path_hits[:5]))
    else:
        add(id="kw-none", category="Phishing heuristics", status="pass",
            title="No credential-bait keywords",
            detail="The address avoids the login/verify/suspended vocabulary.")

    # ---- Brand safety ----------------------------------------------------
    if not is_ip:
        tokens = [t for t in re.split(r"[-_]", sld) if t]
        matched = None

        for b in BRANDS:
            if sld == b:
                matched = {"type": "exact", "b": b}
                break

        if not matched:
            for b in BRANDS:
                if len(b) < 4:
                    continue
                hit = None
                for t in tokens:
                    if t == b and sld != b:
                        hit = {"type": "embedded", "b": b, "t": t}
                        break
                    if t != b and _deleet(t) == b:
                        hit = {"type": "leet", "b": b, "t": t}
                        break
                if hit:
                    matched = hit
                    break
                if _deleet(sld) == b and sld != b:
                    matched = {"type": "leet", "b": b, "t": sld}
                    break
                # Length guards FIRST: they are O(1) and they are already
                # required for a match, so computing the distance before
                # checking them was pure wasted work on hostile input.
                max_d = 2 if len(b) >= 9 else 1
                if len(sld) >= 4 and abs(len(sld) - len(b)) <= 2:
                    d = _lev(sld, b, max_d)
                    if 0 < d <= max_d:
                        matched = {"type": "typo", "b": b, "d": d}
                        break
                for t in tokens:
                    if len(t) >= 5 and t != b and abs(len(t) - len(b)) <= 1:
                        if _lev(t, b, 1) == 1:
                            hit = {"type": "typo-token", "b": b, "t": t}
                            break
                if hit:
                    matched = hit
                    break

        sub_brand = None
        for b in BRANDS:
            if len(b) >= 4 and sld != b and any(
                s == b or b in s or _deleet(s) == b for s in sub_no_www
            ):
                sub_brand = b
                break

        if sub_brand:
            add(id="brand-sub", category="Brand safety", status="fail", delta=-22, critical=True,
                title='"%s" used as a subdomain of %s' % (sub_brand, registrable),
                detail="The real owner of this page is %s — the brand in front is decoration." % registrable)

        if matched:
            kind = matched["type"]
            if kind == "exact":
                add(id="brand", category="Brand safety", status="pass",
                    title='Matches the "%s" brand name' % matched["b"],
                    detail="The registered label equals a well-known brand.")
            elif kind == "leet":
                add(id="brand", category="Brand safety", status="fail", delta=-25, critical=True,
                    title='Character-swap impersonation of "%s"' % matched["b"],
                    detail='"%s" becomes "%s" once digit/letter swaps are undone.' % (matched["t"], matched["b"]))
            elif kind == "typo":
                add(id="brand", category="Brand safety", status="fail",
                    delta=-20 if matched["d"] == 1 else -12,
                    critical=matched["d"] == 1,
                    title='%d character%s away from "%s"' % (
                        matched["d"], "" if matched["d"] == 1 else "s", matched["b"]),
                    detail='"%s" is edit-distance %d from "%s" — the classic typosquat window.'
                           % (sld, matched["d"], matched["b"]))
            elif kind == "typo-token":
                add(id="brand", category="Brand safety", status="fail", delta=-16, critical=True,
                    title='Near-miss of "%s" inside the domain' % matched["b"],
                    detail='"%s" is one edit from "%s".' % (matched["t"], matched["b"]))
            elif kind == "embedded":
                # A brand name glued to credential-bait words ("flipkart-login-
                # verify") is the highest-confidence phishing shape there is, so
                # that combination is critical rather than a simple deduction.
                combo = bool(host_hits)
                add(id="brand", category="Brand safety", status="fail",
                    delta=-18 if combo else -14, critical=combo,
                    title='"%s" embedded in an unrelated domain' % matched["b"],
                    detail="The brand appears as one token of %s%s" % (
                        registrable,
                        ", alongside credential-bait keywords." if combo else "."))

        if not matched and not sub_brand:
            add(id="brand-ok", category="Brand safety", status="pass",
                title="No look-alike collision across %d tracked brands" % len(BRANDS),
                detail="No exact, typo-distance, leet-substituted or embedded brand match.")

    flag_titles = [f["title"] for f in findings if f["status"] in ("fail", "warn")]
    return {
        "findings": findings,
        "flag_titles": flag_titles,
        "host": host,
        "registrable": registrable,
        "is_ip": is_ip,
    }


# ---------------------------------------------------------------------------
# Live feeds (all optional, all cached, all fail-soft)
# ---------------------------------------------------------------------------

_lock = threading.Lock()
_phish_cache = {"ts": 0.0, "set": None}
_domain_cache = {}          # registrable -> {"ts": float, "data": dict}
_PHISH_TTL = 10 * 60
_DOMAIN_TTL = 24 * 3600
_TIMEOUT = 6

FEEDS_ENABLED = os.getenv("TRUSTSCAN_FEEDS", "1") not in ("0", "false", "False")


def _get(url, **kw):
    if requests is None or not FEEDS_ENABLED:
        return None
    try:
        kw.setdefault("timeout", _TIMEOUT)
        r = requests.get(url, **kw)
        return r if r.status_code == 200 else None
    except Exception:
        return None


def _fetch_phish():
    r = _get("https://openphish.com/feed.txt", timeout=_FEED_TIMEOUT)
    now = time.time()
    if r is None:
        with _lock:
            _phish_cache["fail_ts"] = now
            _phish_cache["loading"] = False
        return

    s = set()
    for line in r.text.split("\n"):
        u = line.strip()
        if not u:
            continue
        try:
            h = urlparse(u).hostname or ""
            if h:
                s.add(h)
            s.add(u)
        except Exception:
            pass

    with _lock:
        _phish_cache["ts"] = now
        _phish_cache["set"] = s
        _phish_cache["fail_ts"] = 0.0
        _phish_cache["loading"] = False


def open_phish():
    now = time.time()
    with _lock:
        cached = _phish_cache["set"]
        if cached is not None and now - _phish_cache["ts"] < _PHISH_TTL:
            return cached
        if now - _phish_cache.get("fail_ts", 0.0) < _PHISH_FAIL_TTL:
            return cached
        if _phish_cache.get("loading"):
            return cached
        _phish_cache["loading"] = True

    try:
        threading.Thread(target=_fetch_phish, daemon=True).start()
    except Exception:
        with _lock:
            _phish_cache["loading"] = False

    with _lock:
        return _phish_cache["set"]


def gsb_batch(urls):
    """Google Safe Browsing v4, one batched call. Returns {url: [threat, ...]}."""
    key = os.getenv("GOOGLE_SAFE_BROWSING_KEY")
    if not key or not urls or requests is None or not FEEDS_ENABLED:
        return None
    try:
        r = requests.post(
            "https://safebrowsing.googleapis.com/v4/threatMatches:find",
            params={"key": key},
            json={
                "client": {"clientId": "productfilter-trustscan", "clientVersion": "1.0"},
                "threatInfo": {
                    "threatTypes": [
                        "MALWARE", "SOCIAL_ENGINEERING",
                        "UNWANTED_SOFTWARE", "POTENTIALLY_HARMFUL_APPLICATION",
                    ],
                    "platformTypes": ["ANY_PLATFORM"],
                    "threatEntryTypes": ["URL"],
                    "threatEntries": [{"url": u} for u in urls],
                },
            },
            timeout=_TIMEOUT,
        )
        if r.status_code != 200:
            return None
        out = {}
        for m in r.json().get("matches", []):
            u = (m.get("threat") or {}).get("url")
            if u:
                out.setdefault(u, []).append(m.get("threatType", "THREAT"))
        return out
    except Exception:
        return None


def _rdap_url(domain):
    """Build the RDAP URL with the domain percent-encoded.

    Without quoting, a hostile 'domain' containing ../ or a query string could
    redirect the lookup to another path on rdap.org.
    """
    return "https://rdap.org/domain/" + quote(domain, safe="")


def _rdap(domain):
    r = _get(
        _rdap_url(domain),
        headers={"accept": "application/rdap+json, application/json"},
        timeout=8,
    )
    if r is None:
        return {}
    try:
        j = r.json()
    except Exception:
        return {}
    reg, registrar = None, ""
    for ev in j.get("events", []):
        if ev.get("eventAction") == "registration":
            reg = ev.get("eventDate")
    for e in j.get("entities", []):
        if "registrar" in (e.get("roles") or []):
            v = (e.get("vcardArray") or [None, None])[1]
            if isinstance(v, list):
                for x in v:
                    if isinstance(x, list) and x and x[0] == "fn" and len(x) > 3:
                        registrar = x[3]
            if not registrar and isinstance(e.get("handle"), str):
                registrar = e["handle"]
    return {"reg": reg, "registrar": registrar}


def _dns_resolves(host):
    r = _get(
        "https://dns.google/resolve",
        params={"name": host, "type": "A"},
        headers={"accept": "application/dns-json"},
        timeout=5,
    )
    if r is None:
        return None
    try:
        answers = r.json().get("Answer", [])
    except Exception:
        return None
    return any(a.get("type") == 1 for a in answers)


def domain_intel(registrable, host):
    """Domain age, registrar and DNS resolvability. Cached 24h per domain."""
    now = time.time()
    with _lock:
        hit = _domain_cache.get(registrable)
        if hit and now - hit["ts"] < _DOMAIN_TTL:
            return hit["data"]

    data = {"age_days": None, "registrar": "", "resolves": None}
    rd = _rdap(registrable)
    if rd.get("registrar"):
        data["registrar"] = rd["registrar"]
    if rd.get("reg"):
        try:
            from datetime import datetime, timezone
            iso = rd["reg"].replace("Z", "+00:00")
            t = datetime.fromisoformat(iso)
            if t.tzinfo is None:
                t = t.replace(tzinfo=timezone.utc)
            delta = datetime.now(timezone.utc) - t
            data["age_days"] = max(0, int(delta.days))
        except Exception:
            pass
    data["resolves"] = _dns_resolves(host)

    with _lock:
        if len(_domain_cache) > 2000:
            _domain_cache.clear()
        _domain_cache[registrable] = {"ts": now, "data": data}
    return data


# ---------------------------------------------------------------------------
# Result cache — the thing that actually keeps this fast
# ---------------------------------------------------------------------------

_result_cache = {}      # cache key -> {"ts": float, "res": dict}
_RESULT_TTL = int(os.getenv("TRUSTSCAN_CACHE_TTL", str(24 * 3600)))


def _shape_sig(p):
    """Signature of the URL-level risk signals, for the cache key.

    These findings are properties of the individual URL, NOT of the domain:
    embedded credentials, odd ports, plain HTTP, an embedded redirect target,
    extreme length. Two URLs on the same host with the same shape always score
    the same, so they can safely share a cache entry; two URLs with different
    shapes must not.
    """
    u = p["url"]
    raw = p["raw"]
    q = (u.query or "").lower()
    path_q = (u.path + ("?" + u.query if u.query else "")).lower()
    embedded_redirect = bool(
        re.search(r"(^|&)[^=]*=https?(:|%3a)", q)
        or "http%3a" in path_q or "https%3a" in path_q
    )
    return "%s%s%s%s%s%s" % (
        u.scheme,
        "U" if (u.username or u.password) else "-",
        u.port or "-",
        "R" if embedded_redirect else "-",
        "L" if len(raw) > 120 else "-",
        # bucket, not exact count: keeps hit-rate high across product URLs
        min(2, sum(1 for w in PHISH_WORDS if w in path_q)),
    )


def _cache_key(url, store, deep):
    """Cache per (full host + URL shape), not per registrable domain.

    Keying on the registrable domain alone was a cache-poisoning hole: scoring
    one hostile URL that ENDS at a real retailer's hostname —
    "https://user:pass@evil.tk@amazon.in/" (capped at 38 for embedded
    credentials), or "secure-login-verify.amazon.in" (bait keywords) — wrote
    that capped score under the key "amazon.in", and every genuine Amazon
    listing then read it back for the full 24h TTL and was hidden as
    low-trust. /api/trust let any anonymous caller do it on demand.

    Using the full host plus the URL-shape signature means a poisoned entry can
    only ever describe the exact hostname and URL shape that produced it, while
    ordinary product URLs on a real store still share one entry.
    """
    if not isinstance(url, str):
        url = "" if url is None else str(url)
    p = parse_input(url)
    if p["valid"]:
        base = "%s#%s" % ((p["url"].hostname or "").lower(), _shape_sig(p))
    else:
        base = (url or "")[:120]
    return "%s|%s|%s" % (base, (store or "").lower().strip(), int(bool(deep)))


def clear_cache():
    with _lock:
        _result_cache.clear()
        _domain_cache.clear()
        _phish_cache["set"] = None


# ---------------------------------------------------------------------------
# Scoring
# ---------------------------------------------------------------------------

def _store_fallback_url(store):
    """Map a SerpApi store name to a domain we can score — known names only.

    Guessing a domain from an arbitrary store name (slugify "Evil" -> evil.com)
    invents a subject and then scores it, which is worse than useless: an
    attacker-chosen store name could manufacture a clean-looking domain and a
    high score for a listing whose real link is junk. Only the explicit
    mapping table is trusted.
    """
    if not store:
        return None
    key = store.lower().strip()
    if key in STORE_DOMAIN_HINTS:
        return "https://" + STORE_DOMAIN_HINTS[key]
    for name, dom in STORE_DOMAIN_HINTS.items():
        if name in key:
            return "https://" + dom
    return None


def _is_redirect_host(host):
    return any(host == h or host.endswith("." + h) for h in REDIRECT_HOSTS)

UNRESOLVED_SCORE = int(os.getenv("TRUSTSCAN_UNRESOLVED_SCORE", "55"))

def _unresolved_result(url, store, host):
    """Result for 'we genuinely could not tell who this merchant is'.

    SerpApi returns google.com/search redirects for most listings. The old
    code saw the redirect host, failed to map the store name, then fell
    through to scoring google.com — which is in KNOWN_GOOD_DOMAINS. So every
    unknown shop rendered as "96 - Verified major retailer".
    """
    score = int(clamp(UNRESOLVED_SCORE, 0, MAX_SCORE))
    return {
        "url": url, "store": store, "valid": True, "host": host, "domain": "",
        "score": score, "risk": risk_of(score),
        "badge": "watch" if score >
        MIN_SCORE else "risk",
        "listed": False, "listed_by": [],
        "flags": ["Merchant not identified — the link goes via Google Shopping"],
        "known_good": False, "via_store_name": False, "unresolved_merchant": True,
        "verdict": ("We could not confirm which shop this is — the link goes "
                    "through Google Shopping rather than to a named seller."),
    }


def _normalize_items(items):
    norm = []
    for it in items:
        if isinstance(it, dict):
            url, store = it.get("url") or it.get("link") or "", it.get("store") or ""
        else:
            url, store = it or "", ""
        if not isinstance(url, str):
            url = "" if url is None else str(url)
        if not isinstance(store, str):
            store = str(store)
        norm.append((url, store))
    return norm


def score_many(items, deep=False):
    norm = _normalize_items(items)
    score_urls(items, deep=deep)
    results = []
    for url, store in norm:
        k = _cache_key(url, store, deep)
        with _lock:
            hit = _result_cache.get(k)
        res = dict(hit["res"]) if hit else dict(NO_LINK_RESULT)
        res["url"], res["store"] = url, store
        results.append(res)
    return results


def score_urls(items, deep=False, use_ai=False):
    """Score a batch of listings.

    
    norm = _normalize_items(items)

    out = {}
    todo = []
    now = time.time()

    # 1. serve from cache
    for url, store in norm:
        k = _cache_key(url, store, deep)
        with _lock:
            hit = _result_cache.get(k)
        if hit and now - hit["ts"] < _RESULT_TTL:
            out[url] = dict(hit["res"])
        else:
            todo.append((url, store, k))

    if not todo:
        return out

    # 2. one shared feed pull for the whole batch
    phish = open_phish()
    parsed_map = {}
    hrefs = []
    for url, store, k in todo:
        target = url
        p = parse_input(target)
        # SerpApi sometimes returns a Google redirect — score the merchant
        # the listing claims to be from instead of scoring google.com.
        if p["valid"] and _is_redirect_host((p["url"].hostname or "").lower()):
            alt = _store_fallback_url(store)
            if alt:
                p = parse_input(alt)
                p["via_store_name"] = True
            else:
                p = {"valid": False, "unresolved": True,
                     "host": (p["url"].hostname or "").lower()}
        if not p["valid"] and store and not (target or "").strip():
            alt = _store_fallback_url(store)
            if alt:
                p = parse_input(alt)
                p["via_store_name"] = True
        parsed_map[k] = p
        if p["valid"]:
            hrefs.append(p["href"])

    gsb = gsb_batch(hrefs[:500]) if hrefs else None

    # 3. deep mode warms the domain cache for each unique registrable
    if deep:
        seen = set()
        for url, store, k in todo:
            p = parsed_map[k]
            if not p["valid"]:
                continue
            heur = analyze(p)
            p["_heur"] = heur
            if not heur["is_ip"] and heur["registrable"] not in seen:
                seen.add(heur["registrable"])
                domain_intel(heur["registrable"], heur["host"])

    # 4. score
    for url, store, k in todo:
        p = parsed_map[k]
        if not p["valid"] and p.get("unresolved"):
            res = _unresolved_result(url, store, p.get("host", ""))
            out[url] = res
            with _lock:
                _result_cache[k] = {"ts": now, "res": dict(res)}
            continue
        if not p["valid"]:
            res = {
                "url": url, "store": store, "valid": False,
                "score": None, "risk": "Unknown", "badge": "watch",
                "listed": False, "listed_by": [], "flags": [p.get("error", "Unparseable URL")],
                "domain": "", "verdict": "This listing has no usable address to check.",
            }
            out[url] = res
            with _lock:
                _result_cache[k] = {"ts": now, "res": dict(res)}
            continue

        heur = p.get("_heur") or analyze(p)
        score = 100 + sum(f.get("delta", 0) for f in heur["findings"])
        flags = list(heur["flag_titles"])
        listed_by = []

        href = p["href"]
        host = heur["host"]
        if phish:
            if href in phish or href.rstrip("/") in phish or host in phish:
                listed_by.append("OpenPhish")
        if gsb and href in gsb:
            listed_by.append("Google Safe Browsing: " + ", ".join(sorted(set(gsb[href]))))

        domain_data = None
        if deep and not heur["is_ip"]:
            with _lock:
                cached = _domain_cache.get(heur["registrable"])
            if cached:
                domain_data = cached["data"]
                age = domain_data.get("age_days")
                if age is not None:
                    if age < 30:
                        score -= 15
                        flags.append("Domain registered only %d days ago" % age)
                    elif age < 180:
                        score -= 8
                        flags.append("Young domain (under 6 months)")
                    elif age / 365.25 >= 10:
                        score += 12
                    elif age / 365.25 >= 5:
                        score += 8
                if domain_data.get("resolves") is False:
                    score -= 10
                    flags.append("Hostname does not resolve in public DNS")

        listed = bool(listed_by)
        if any(f.get("critical") for f in heur["findings"]) and score > CRITICAL_CAP:
            score = CRITICAL_CAP
        if listed and score > LISTED_CAP:
            score = LISTED_CAP

        # Verified marketplaces get a floor so a messy affiliate URL can't
        # bury a real retailer. The floor is NOT applied when the URL itself is
        # dangerous — a blocklist hit, a critical finding, embedded credentials
        # (the user:pass@host@realhost trick) or a plain-HTTP downgrade. Those
        # attacks all end at a legitimate hostname, so the floor would
        # otherwise launder them into a high score.
        floor_blocked = (
            listed
            or any(f.get("critical") for f in heur["findings"])
            or any(f["id"] in ("userinfo", "port", "redir") for f in heur["findings"])
            or p["url"].scheme != "https"
        )
        if not floor_blocked and heur["registrable"] in KNOWN_GOOD_DOMAINS:
            score = max(score, KNOWN_GOOD_FLOOR)
            flags = [f for f in flags if "brand" not in f.lower()]

        known = heur["registrable"] in KNOWN_GOOD_DOMAINS
        aged = (domain_data or {}).get("age_days")
        if not known and not (aged and aged > 365 * 3):
            score = min(score, UNKNOWN_CAP)

        score = int(clamp(round(score), 0, MAX_SCORE))

        res = {
            "url": url,
            "store": store,
            "valid": True,
            "host": host,
            "domain": heur["registrable"],
            "score": score,
            "risk": risk_of(score),
            "badge": badge_of(score),
            "listed": listed,
            "listed_by": listed_by,
            "flags": flags[:6],
            "known_good": heur["registrable"] in KNOWN_GOOD_DOMAINS,
            "via_store_name": bool(p.get("via_store_name")),
        }
        if domain_data:
            res["domain_age_days"] = domain_data.get("age_days")
            res["registrar"] = domain_data.get("registrar", "")

        res["verdict"] = default_verdict(res)
        out[url] = res
        with _lock:
            if len(_result_cache) > 5000:
                _result_cache.clear()
            _result_cache[k] = {"ts": now, "res": dict(res)}

    return out


def score_url(url, store="", deep=False):
    return score_urls([{"url": url, "store": store}], deep=deep).get(url)


def default_verdict(res):
    """One-line plain-English summary, used when the AI layer is unavailable."""
    if not res.get("valid"):
        return "No usable address to check."
    s = res["score"]
    if res.get("listed"):
        return "Flagged on a live threat blocklist — do not open."
    if res.get("known_good"):
        return "Verified major retailer."
    if s >= 80:
        return "Long-established domain, no risk signals found."
    if s >= 65:
        return "No risk signals — but this seller isn't one we recognise."
    if s > 50:
        return "Mixed signals — check the seller before paying."
    if s >= 30:
        return "Multiple risk signals on this domain."
    return "Strong impersonation or scam signals — avoid."


# ---------------------------------------------------------------------------
# Filtering — the part ProductFilter calls
# ---------------------------------------------------------------------------

MIN_SCORE = int(os.getenv("TRUSTSCAN_MIN_SCORE", "50"))
REQUIRE_SCORE = os.getenv("TRUSTSCAN_REQUIRE_SCORE", "0") in ("1", "true", "True")
ENABLED = os.getenv("TRUSTSCAN_ENABLED", "1") not in ("0", "false", "False")


def is_trusted(res, minimum=None):
    """True when a listing may be shown. Strictly above the threshold.

    A listing whose URL could not be parsed is ALWAYS rejected, regardless of
    REQUIRE_SCORE. That case covers `javascript:`, `data:`, `file:` and other
    non-http schemes, which must never reach an href attribute — treating them
    as "unknown, so probably fine" would be an XSS vector.
    """
    minimum = MIN_SCORE if minimum is None else minimum
    if not res:
        return not REQUIRE_SCORE
    if res.get("valid") is False:
        return False
    if res.get("score") is None:
        return not REQUIRE_SCORE
    return res["score"] > minimum


def safe_link(url):
    """Return the URL only if it is a plain http(s) address, else '#'.

    Defence in depth for templates: even if a bad URL somehow survives
    filtering, it can never render as an executable scheme.
    """
    p = parse_input(url or "")
    if not p["valid"]:
        return "#"
    return p["href"]


NO_LINK_RESULT = {
    "valid": False, "score": None, "risk": "Unknown", "badge": "risk",
    "listed": False, "listed_by": [], "flags": ["Listing has no usable link"],
    "domain": "", "verdict": "This listing has no address to check.",
}


def annotate_offers(offers, deep=False):
    """Attach a `trust` dict to each offer. Offers are dicts with link/store.

    An offer whose link is missing, None or non-http gets an explicitly
    invalid result rather than an empty dict — an empty dict reads as
    "unknown", which is_trusted would let through.
    """
    if not ENABLED or not offers:
        return offers

    links = []
    for o in offers:
        link = o.get("link") or ""
        if not isinstance(link, str):
            link = str(link)
        links.append(link)

    scored = score_urls(
        [{"url": link, "store": (o.get("store") or "")}
         for link, o in zip(links, offers)],
        deep=deep,
    )
    for link, o in zip(links, offers):
        o["trust"] = scored.get(link) or dict(NO_LINK_RESULT)
    return offers


def filter_offers(offers, minimum=None, deep=False):
    """Split offers into (kept, hidden) by trust score."""
    if not ENABLED:
        return offers, []
    annotate_offers(offers, deep=deep)
    kept, hidden = [], []
    for o in offers:
        (kept if is_trusted(o.get("trust"), minimum) else hidden).append(o)
    return kept, hidden