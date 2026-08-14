"""
Robustness / bug-hunting harness for ProductFilter.

Where pentest.py looks for attackers, this one looks for crashes: malformed
SerpApi payloads, missing fields, absurd numbers, unicode, concurrency, and
the awkward edge cases that show up in production logs at 3am.

    python3 bugtest.py
"""

import os
import re
import sys
import types
import threading
import traceback

os.environ.setdefault("TRUSTSCAN_FEEDS", "0")
os.environ.setdefault("AI_ENABLED", "0")
os.environ.pop("SENTRY_DSN", None)

RESULTS = []


def check(name, passed, detail=""):
    RESULTS.append((name, passed, detail))
    print("  %-4s %-56s %s" % ("PASS" if passed else "BUG", name, detail))


MOCK = {"shopping_results": []}


class _MockSearch:
    def __init__(self, params):
        self.params = params

    def get_dict(self):
        return MOCK


for name, mod in (("serpapi", None), ("sentry_sdk", None)):
    pass

if "serpapi" not in sys.modules:
    m = types.ModuleType("serpapi")
    m.GoogleSearch = _MockSearch
    sys.modules["serpapi"] = m
if "sentry_sdk" not in sys.modules:
    s = types.ModuleType("sentry_sdk")
    s.init = lambda **kw: None
    s.capture_exception = lambda e=None: None
    i = types.ModuleType("sentry_sdk.integrations")
    f = types.ModuleType("sentry_sdk.integrations.flask")
    f.FlaskIntegration = lambda *a, **k: None
    sys.modules["sentry_sdk"] = s
    sys.modules["sentry_sdk.integrations"] = i
    sys.modules["sentry_sdk.integrations.flask"] = f

import trustscan
import ai_helper
import app as productfilter

productfilter.GoogleSearch = _MockSearch
productfilter.app.config["TESTING"] = True
productfilter.app.config["PROPAGATE_EXCEPTIONS"] = False
client = productfilter.app.test_client()


def reset():
    productfilter.cache.clear()
    productfilter.request_log.clear()
    productfilter.blocked_ips.clear()
    trustscan.clear_cache()


def render(items, query="iphone 16", path="/", field="product_query"):
    reset()
    MOCK["shopping_results"] = items
    return client.post(path, data={field: query})


# ===========================================================================
print("\n" + "=" * 74)
print("1. MALFORMED SERPAPI PAYLOADS")
print("=" * 74)

BAD_PAYLOADS = [
    ([], "empty result list"),
    ([{}], "completely empty item"),
    ([{"title": "X"}], "item with no price, link or source"),
    ([{"title": None, "price": None, "source": None, "link": None,
       "thumbnail": None}], "all fields None"),
    ([{"title": "X", "price": "not a number", "source": "S",
       "link": "https://a.com"}], "unparseable price"),
    ([{"title": "X", "price": "", "source": "S", "link": "https://a.com"}], "empty price"),
    ([{"title": "X", "price": "₹0", "source": "S", "link": "https://a.com"}], "zero price"),
    ([{"title": "X", "price": "₹-500", "source": "S", "link": "https://a.com"}], "negative price"),
    ([{"title": "X", "price": "₹" + "9" * 40, "source": "S",
       "link": "https://a.com"}], "absurdly large price"),
    ([{"title": "X" * 5000, "price": "₹100", "source": "S" * 5000,
       "link": "https://a.com"}], "5000-char title and source"),
    ([{"title": "🛒📱🎉 ünïcødé ĥéllo", "price": "₹1,00,000", "source": "Ⓐmazon",
       "link": "https://a.com"}], "unicode and emoji"),
    ([{"title": "X\x00null", "price": "₹100", "source": "S",
       "link": "https://a.com"}], "null byte in title"),
    ([{"title": "X", "price": "₹100", "source": "S", "link": ""}], "empty link"),
    ([{"title": "X", "price": "₹100", "source": "S"}], "missing link key"),
]

for payload, label in BAD_PAYLOADS:
    try:
        r = render(payload)
        ok = r.status_code == 200
        detail = "" if ok else "HTTP %s" % r.status_code
    except Exception as e:
        ok, detail = False, "%s: %s" % (type(e).__name__, e)
    check(label, ok, detail)

# the whole SerpApi response being the wrong shape
for bad, label in [({}, "response with no shopping_results"),
                   ({"shopping_results": None}, "shopping_results is None"),
                   ({"shopping_results": "oops"}, "shopping_results is a string"),
                   ({"error": "Invalid API key"}, "SerpApi error response")]:
    try:
        reset()
        MOCK.clear()
        MOCK.update(bad if isinstance(bad, dict) else {})
        r = client.post("/", data={"product_query": "test"})
        ok = r.status_code == 200
        detail = "" if ok else "HTTP %s" % r.status_code
    except Exception as e:
        ok, detail = False, "%s: %s" % (type(e).__name__, e)
    check(label, ok, detail)
MOCK.clear()
MOCK["shopping_results"] = []

# ===========================================================================
print("\n" + "=" * 74)
print("2. QUERY INPUT EDGE CASES")
print("=" * 74)

QUERIES = [
    ("", "empty query"),
    ("  ", "whitespace-only query"),
    ("ab", "query below minimum length"),
    ("x" * 5000, "5000-char query"),
    ("🍎🍎🍎", "emoji-only query"),
    ("../../etc/passwd", "path traversal string"),
    ("' OR 1=1 --", "SQL injection string"),
    ("{{7*7}}", "Jinja template expression"),
    ("${7*7}", "template literal"),
    ("%00%0a%0d", "encoded control characters"),
    ("a\nb\rc\td", "raw control characters"),
    ("-" * 200, "punctuation run"),
]
def _without_asset_hashes(body):
    """Drop ?v=<hash> query strings before scanning a page for a literal.

    Static asset URLs carry a content hash (see static_url in app.py), and a
    hex hash can contain any digit pair — one of them happened to contain "49",
    which made the SSTI probe below report an evaluation that never happened.
    """
    return re.sub(r"\?v=[0-9a-f]+", "", body)


for q, label in QUERIES:
    try:
        r = render([], query=q)
        ok = r.status_code == 200
        body = r.get_data(as_text=True)
        if "{{7*7}}" == q and "49" in _without_asset_hashes(body):
            ok, label = False, label + " (SSTI: evaluated!)"
        detail = "" if ok else "HTTP %s" % r.status_code
    except Exception as e:
        ok, detail = False, "%s: %s" % (type(e).__name__, e)
    check(label, ok, detail)

# same through the category route
for q, label in [("", "category: empty search"), ("x" * 3000, "category: huge search")]:
    try:
        r = render([], query=q, path="/category/mobiles", field="search")
        ok = r.status_code == 200
        detail = "" if ok else "HTTP %s" % r.status_code
    except Exception as e:
        ok, detail = False, "%s: %s" % (type(e).__name__, e)
    check(label, ok, detail)

# ===========================================================================
print("\n" + "=" * 74)
print("3. ROUTING EDGE CASES")
print("=" * 74)

ROUTES = [
    ("/category/", "empty category slug"),
    ("/category/does-not-exist", "unknown category"),
    ("/category/" + "x" * 2000, "very long category slug"),
    ("/category/%2e%2e%2f%2e%2e%2fetc", "encoded traversal in slug"),
    ("/category/mobiles/extra/segments", "extra path segments"),
    ("/food/nonexistent-brand", "unknown food brand"),
    ("/food/mcdonalds/not-a-real-item", "unknown food item"),
    ("/api/price-check", "price-check with no title"),
    ("/api/price-check?title=ab", "price-check with short title"),
    ("/api/trust?url=", "trust API with empty url"),
    ("/manifest.json", "PWA manifest"),
    ("/sw.js", "service worker"),
]
for path, label in ROUTES:
    try:
        r = client.get(path, follow_redirects=True)
        reset()
        ok = r.status_code in (200, 400, 404)
        detail = "HTTP %s" % r.status_code
        if r.status_code >= 500:
            ok = False
    except Exception as e:
        ok, detail = False, "%s: %s" % (type(e).__name__, e)
    check(label, ok, detail)

# HTTP verb fuzzing
for verb in ("GET", "POST", "PUT", "DELETE", "PATCH", "HEAD", "OPTIONS"):
    try:
        r = client.open("/", method=verb)
        reset()
        ok = r.status_code < 500
        detail = "HTTP %s" % r.status_code
    except Exception as e:
        ok, detail = False, "%s: %s" % (type(e).__name__, e)
    check("verb %s handled" % verb, ok, detail)

# ===========================================================================
print("\n" + "=" * 74)
print("4. TRUSTSCAN INPUT ROBUSTNESS")
print("=" * 74)

WEIRD_URLS = [
    None, "", " ", "http://", "https://", "://no-scheme", "http:///empty-host",
    "https://.", "https://..", "https://-.com", "https://a..b.com",
    "https://" + "a" * 300 + ".com", "https://xn--.com", "https://[::1]",
    "https://user@:80", "https://host:99999/", "https://host:-1/",
    "https://exam ple.com", "https://exаmple.com",   # cyrillic а
    "https://‮evil.com", "1.2.3.4", "localhost", "https://localhost:5000",
    "ftp://files.example.com/x", "//protocol-relative.com/x",
    "https://a.com/" + "%" * 500, "https://a.com/?" + "a=1&" * 2000,
]
crashes = 0
for u in WEIRD_URLS:
    try:
        res = trustscan.score_url(u)
        trustscan.is_trusted(res)
        trustscan.safe_link(u)
    except Exception as e:
        crashes += 1
        check("score_url(%r)" % (u,), False, "%s: %s" % (type(e).__name__, e))
check("%d hostile URL shapes scored without crashing" % len(WEIRD_URLS), crashes == 0)

# batch API with junk input
try:
    trustscan.score_urls([None, "", {}, {"url": None}, {"url": 12345},
                          {"link": "https://a.com"}, 12345, [], {"url": "https://a.com"}])
    check("score_urls tolerates a junk batch", True)
except Exception as e:
    check("score_urls tolerates a junk batch", False, "%s: %s" % (type(e).__name__, e))

# offer filtering with malformed offers
try:
    offers = [{"store": "A", "price": 100, "link": "https://amazon.in/x"},
              {"store": None, "price": None, "link": None},
              {}, {"link": "javascript:alert(1)", "store": "Evil", "price": 1}]
    kept, hidden = trustscan.filter_offers(offers)
    ok = all(o.get("link", "").startswith("http") for o in kept)
    check("filter_offers drops malformed and unsafe offers", ok,
          "%d kept, %d hidden" % (len(kept), len(hidden)))
except Exception as e:
    check("filter_offers drops malformed and unsafe offers", False,
          "%s: %s" % (type(e).__name__, e))

# ===========================================================================
print("\n" + "=" * 74)
print("5. CONCURRENCY")
print("=" * 74)

errors = []


def hammer(n):
    try:
        for i in range(20):
            trustscan.score_url("https://shop%d-%d.com/p" % (n, i))
            trustscan.score_url("https://amazon.in/dp/%d" % i)
            ai_helper.cache_put("k%d-%d" % (n, i), "v")
            ai_helper.cache_get("k%d-%d" % (n, i))
    except Exception:
        errors.append(traceback.format_exc())


threads = [threading.Thread(target=hammer, args=(n,)) for n in range(12)]
for t in threads:
    t.start()
for t in threads:
    t.join()
check("12 threads x 20 scores, no race conditions", not errors,
      errors[0].splitlines()[-1] if errors else "")

req_errors = []


def hammer_http(n):
    try:
        c = productfilter.app.test_client()
        for i in range(10):
            MOCK["shopping_results"] = [
                {"title": "Item", "price": "₹100", "source": "Amazon.in",
                 "thumbnail": "", "link": "https://amazon.in/dp/x"}]
            r = c.post("/", data={"product_query": "thread %d %d" % (n, i)})
            if r.status_code >= 500:
                req_errors.append("HTTP %s" % r.status_code)
    except Exception:
        req_errors.append(traceback.format_exc())


reset()
productfilter.RATE_LIMIT = 10000          # concurrency test, not a rate-limit test
threads = [threading.Thread(target=hammer_http, args=(n,)) for n in range(8)]
for t in threads:
    t.start()
for t in threads:
    t.join()
check("8 concurrent search requests, no 5xx", not req_errors,
      req_errors[0] if req_errors else "")
productfilter.RATE_LIMIT = 50
reset()

# ===========================================================================
print("\n" + "=" * 74)
print("6. AI LAYER FAILURE MODES")
print("=" * 74)

_orig_avail = ai_helper.available
_orig_ask = ai_helper.ask_ai
ai_helper.available = lambda: True
ai_helper._budget_ok = lambda: True

BAD_AI_REPLIES = [
    (None, "provider returned nothing"),
    ("", "empty string"),
    ("I'm sorry, I can't help with that.", "refusal prose"),
    ("{broken json", "malformed JSON"),
    ('{"a.com": 12345}', "wrong value type"),
    ('["not", "an", "object"]', "JSON array instead of object"),
    ("```json\n{\"a.com\": \"trust\"}\n```", "fenced JSON"),
    ('{"a.com": "maybe"}', "invalid vote value"),
    ("x" * 100000, "100KB response"),
]
for reply, label in BAD_AI_REPLIES:
    ai_helper.ask_ai = lambda p, _r=reply: _r
    try:
        rows = [{"valid": True, "domain": "a.com", "score": 50, "risk": "Elevated",
                 "badge": "watch", "listed": False, "known_good": False, "flags": []}]
        ai_helper.tiebreak(rows)
        ai_helper.verdicts_for(rows)
        ok = isinstance(rows[0]["score"], int)
        detail = ""
    except Exception as e:
        ok, detail = False, "%s: %s" % (type(e).__name__, e)
    check("survives: " + label, ok, detail)


def boom(prompt):
    raise Exception("network down")


ai_helper.ask_ai = boom
try:
    rows = [{"valid": True, "domain": "b.com", "score": 50, "risk": "Elevated",
             "badge": "watch", "listed": False, "known_good": False, "flags": []}]
    ai_helper.tiebreak(rows)
    check("survives: provider raises an exception", True)
except Exception as e:
    check("survives: provider raises an exception", False, "%s: %s" % (type(e).__name__, e))

ai_helper.ask_ai = _orig_ask
ai_helper.available = _orig_avail

# a corrupt cache file must not take the app down
try:
    with open("/tmp/corrupt_ai_cache.json", "w") as fh:
        fh.write("{not json at all")
    ai_helper.CACHE_PATH = "/tmp/corrupt_ai_cache.json"
    ai_helper._cache = None
    ai_helper.cache_get("anything")
    check("corrupt AI cache file is recovered", True)
except Exception as e:
    check("corrupt AI cache file is recovered", False, "%s: %s" % (type(e).__name__, e))

# ===========================================================================
print("\n" + "=" * 74)
print("7. FUNCTIONAL CORRECTNESS")
print("=" * 74)

reset()
MOCK["shopping_results"] = [
    {"title": "Apple iPhone 16 128GB", "price": "₹75,000", "source": "Croma",
     "thumbnail": "", "link": "https://www.croma.com/x"},
    {"title": "Apple iPhone 16 128GB", "price": "₹69,999", "source": "Flipkart",
     "thumbnail": "", "link": "https://www.flipkart.com/x"},
    {"title": "Apple iPhone 16 128GB", "price": "₹71,900", "source": "Amazon.in",
     "thumbnail": "", "link": "https://www.amazon.in/x"},
]
html = client.post("/", data={"product_query": "iphone 16"}).get_data(as_text=True)
i_cheap = html.find("69,999")
i_mid = html.find("71,900")
check("cheapest offer is listed first", 0 < i_cheap < i_mid)
check("savings line reflects max minus min", "5,001" in html,
      "expected ₹5,001 (75,000 - 69,999)")
check("all three stores survive filtering",
      all(s in html for s in ("Croma", "Flipkart", "Amazon.in")))

reset()
MOCK["shopping_results"] = [
    {"title": "Item", "price": "₹100", "source": "Scam", "thumbnail": "",
     "link": "https://fl1pkart.com/x"}]
html = client.post("/", data={"product_query": "item"}).get_data(as_text=True)
check("page with every listing filtered still renders",
      "low-trust listing" in html and "Traceback" not in html)

reset()
r = client.get("/api/trust?url=https://www.amazon.in/dp/X")
data = r.get_json()
check("trust API returns a well-formed body",
      isinstance(data, dict) and "score" in data and "shown_on_site" in data)
check("trust API reports the active threshold",
      data.get("threshold") == trustscan.MIN_SCORE)

# threshold is honoured, and it is strictly "greater than"
saved = trustscan.MIN_SCORE
trustscan.MIN_SCORE = 90
check("raising the threshold hides mid-scoring stores",
      not trustscan.is_trusted({"valid": True, "score": 85}))
trustscan.MIN_SCORE = 50
check("a score exactly equal to the threshold is hidden",
      not trustscan.is_trusted({"valid": True, "score": 50}))
check("one point above the threshold is shown",
      trustscan.is_trusted({"valid": True, "score": 51}))
trustscan.MIN_SCORE = saved

# disabling the feature must restore the old behaviour
trustscan.ENABLED = False
try:
    offers = [{"store": "Evil", "price": 1, "link": "https://fl1pkart.com/x"}]
    kept, hidden = trustscan.filter_offers(offers)
    check("TRUSTSCAN_ENABLED=0 disables filtering", len(kept) == 1 and not hidden)
finally:
    trustscan.ENABLED = True

# ===========================================================================
print("\n" + "=" * 74)
bugs = [r for r in RESULTS if not r[1]]
print("SUMMARY: %d checks, %d passed, %d FAILED" %
      (len(RESULTS), len(RESULTS) - len(bugs), len(bugs)))
print("=" * 74)
if bugs:
    for name, _, detail in bugs:
        print("  %s %s" % (name, ("— " + detail) if detail else ""))
    sys.exit(1)
print("No bugs found.")
