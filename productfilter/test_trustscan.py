"""
Offline smoke test for the TrustScan integration.

Runs the whole Flask app against a mocked SerpApi payload — no API key, no
network — and asserts that scam listings are filtered out while real
retailers survive. Run it with:

    TRUSTSCAN_FEEDS=0 python3 test_trustscan.py
"""

import os
import sys

# keep the test hermetic: no live feeds, no AI, no Sentry
os.environ.setdefault("TRUSTSCAN_FEEDS", "0")
os.environ.setdefault("AI_ENABLED", "0")
os.environ.pop("SENTRY_DSN", None)

import trustscan

# ---------------------------------------------------------------------------
# 1. engine-level checks
# ---------------------------------------------------------------------------

CASES = [
    # (url, expected_shown, label)
    ("https://www.amazon.in/dp/B0CHX1W1XY",                 True,  "Amazon India"),
    ("https://www.flipkart.com/apple-iphone-16/p/itm123",   True,  "Flipkart"),
    ("https://www.croma.com/apple-iphone-16/p/305001",      True,  "Croma"),
    ("https://www.reliancedigital.in/iphone-16/p/49312",    True,  "Reliance Digital"),
    ("https://arnazon.in/iphone-16-offer",                  False, "Typosquat of amazon"),
    ("https://flipkart-login-verify.tk/deal",               False, "Phishing TLD + bait words"),
    ("https://amazon.secure-billing-update.xyz/pay",        False, "Brand as subdomain"),
    ("http://192.168.44.7/cheap-iphone",                    False, "Raw IP over HTTP"),
    ("https://fl1pkart.com/iphone",                         False, "Leetspeak impersonation"),
    ("https://bit.ly/3xYzAbc",                              False, "Shortener hiding target"),
]

print("=" * 68)
print("TrustScan engine  (threshold: score must be > %d)" % trustscan.MIN_SCORE)
print("=" * 68)

failures = []
for url, expected_shown, label in CASES:
    res = trustscan.score_url(url)
    shown = trustscan.is_trusted(res)
    ok = shown == expected_shown
    if not ok:
        failures.append((label, res["score"], expected_shown, shown))
    print("%-4s %-3s  %-34s %s" % (
        "PASS" if ok else "FAIL",
        res["score"],
        label,
        "shown" if shown else "HIDDEN",
    ))
    if not shown and res.get("flags"):
        print("           reason: %s" % res["flags"][0])

# ---------------------------------------------------------------------------
# 2. full request cycle against a mocked SerpApi
# ---------------------------------------------------------------------------

MOCK_SHOPPING = {
    "shopping_results": [
        {"title": "Apple iPhone 16 128GB Black", "price": "₹71,900",
         "source": "Amazon.in", "thumbnail": "", "link": "https://www.amazon.in/dp/B0CHX1W1XY"},
        {"title": "Apple iPhone 16 128GB Black", "price": "₹69,999",
         "source": "Flipkart", "thumbnail": "", "link": "https://www.flipkart.com/apple-iphone-16/p/itm1"},
        {"title": "Apple iPhone 16 128GB", "price": "₹70,499",
         "source": "Croma", "thumbnail": "", "link": "https://www.croma.com/apple-iphone-16/p/305001"},
        # the three below must never reach the page
        {"title": "Apple iPhone 16 128GB CHEAP", "price": "₹31,999",
         "source": "iphone-deals", "thumbnail": "",
         "link": "https://amazon.secure-billing-update.xyz/iphone16"},
        {"title": "Apple iPhone 16 offer", "price": "₹28,500",
         "source": "MegaDeals", "thumbnail": "", "link": "https://fl1pkart.com/iphone-16"},
        {"title": "iPhone 16 mobile lowest price", "price": "₹25,000",
         "source": "BestBuyIndia", "thumbnail": "",
         "link": "https://flipkart-login-verify.tk/iphone"},
    ]
}


class _MockSearch:
    def __init__(self, params):
        self.params = params

    def get_dict(self):
        return MOCK_SHOPPING


# Stub the SerpApi + Sentry SDKs so the test needs no third-party installs.
import types

if "serpapi" not in sys.modules:
    _serpapi = types.ModuleType("serpapi")
    _serpapi.GoogleSearch = _MockSearch
    sys.modules["serpapi"] = _serpapi

if "sentry_sdk" not in sys.modules:
    _sentry = types.ModuleType("sentry_sdk")
    _sentry.init = lambda **kw: None
    _sentry.capture_exception = lambda e=None: None
    _integrations = types.ModuleType("sentry_sdk.integrations")
    _flask_int = types.ModuleType("sentry_sdk.integrations.flask")
    _flask_int.FlaskIntegration = lambda *a, **k: None
    sys.modules["sentry_sdk"] = _sentry
    sys.modules["sentry_sdk.integrations"] = _integrations
    sys.modules["sentry_sdk.integrations.flask"] = _flask_int

import app as productfilter
productfilter.GoogleSearch = _MockSearch          # patch SerpApi
productfilter.cache.clear()
productfilter.app.config["TESTING"] = True

client = productfilter.app.test_client()

print()
print("=" * 68)
print("Full search request  (mocked SerpApi: 3 real stores + 3 scams)")
print("=" * 68)

resp = client.post("/", data={"product_query": "iphone 16"})
html = resp.get_data(as_text=True)

# A scam domain may legitimately appear as *text* inside the "why were these
# hidden" table. What must never appear is a clickable link to one.
def not_linked(needle, page):
    return ('href="https://' + needle) not in page and ("href=\"http://" + needle) not in page


checks = [
    ("status 200",                      resp.status_code == 200),
    ("Amazon shown",                    "amazon.in" in html.lower()),
    ("Flipkart shown",                  "flipkart.com/apple-iphone-16" in html),
    ("scam .xyz not linked",            not_linked("amazon.secure-billing-update.xyz", html)),
    ("leetspeak fl1pkart not linked",   not_linked("fl1pkart.com", html)),
    ("phishing .tk not linked",         not_linked("flipkart-login-verify.tk", html)),
    ("scams listed in hidden notice",   "secure-billing-update.xyz" in html),
    ("hidden-count notice rendered",    "low-trust listing" in html),
    ("trust badge rendered",            'class="trust trust-' in html),
    ("receipt layout rendered",         'class="receipt"' in html),
    ("alerts modal preserved",          'id="alert-modal"' in html),
    ("PWA manifest preserved",          '/manifest.json' in html),
]

for label, ok in checks:
    print("%-4s %s" % ("PASS" if ok else "FAIL", label))
    if not ok:
        failures.append((label, None, True, False))

# category page
resp2 = client.post("/category/mobiles", data={"search": "iphone 16"})
html2 = resp2.get_data(as_text=True)
cat_checks = [
    ("category status 200",   resp2.status_code == 200),
    ("category receipt",      'class="receipt"' in html2),
    ("category scam not linked", not_linked("fl1pkart.com", html2)),
    ("category accent theme", 'data-c="mobiles"' in html2),
]
print()
for label, ok in cat_checks:
    print("%-4s %s" % ("PASS" if ok else "FAIL", label))
    if not ok:
        failures.append((label, None, True, False))

# other routes still alive
print()
for path in ("/", "/health", "/api/trust-status", "/api/trust?url=amazon.in", "/food"):
    r = client.get(path, follow_redirects=True)
    ok = r.status_code == 200
    print("%-4s GET %s -> %s" % ("PASS" if ok else "FAIL", path, r.status_code))
    if not ok:
        failures.append((path, None, 200, r.status_code))

print()
print("=" * 68)
if failures:
    print("%d FAILURE(S):" % len(failures))
    for f in failures:
        print("   ", f)
    sys.exit(1)
print("ALL CHECKS PASSED")
