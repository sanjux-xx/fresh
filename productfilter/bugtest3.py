"""
Third robustness pass: the surfaces added since the last bug hunt.

Alerts on category pages, the price_value the template depends on, the
install prompt, the shared partials, and the status pill.

    python3 bugtest3.py
"""

import os
import re
import sys
import types

os.environ.setdefault("TRUSTSCAN_FEEDS", "0")
os.environ.setdefault("AI_ENABLED", "0")
os.environ.pop("SENTRY_DSN", None)

RESULTS = []


def check(name, passed, detail=""):
    RESULTS.append((name, passed, detail))
    print("  %-4s %-58s %s" % ("PASS" if passed else "BUG", name, detail))


MOCK = {"shopping_results": []}


class _MS:
    def __init__(self, p):
        pass

    def get_dict(self):
        return MOCK


if "serpapi" not in sys.modules:
    m = types.ModuleType("serpapi")
    m.GoogleSearch = _MS
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
import app as productfilter

productfilter.GoogleSearch = _MS
productfilter.app.config["TESTING"] = True
productfilter.RATE_LIMIT = 100000
client = productfilter.app.test_client()


def reset():
    productfilter.cache.clear()
    productfilter.request_log.clear()
    productfilter.blocked_ips.clear()
    trustscan.clear_cache()


def item(title, price, source="Amazon.in", link="https://www.amazon.in/dp/X"):
    return {"title": title, "price": price, "source": source,
            "thumbnail": "", "link": link}


# ===========================================================================
print("\n" + "=" * 76)
print("1. price_value — the field the alert button depends on")
print("=" * 76)

CASES = [
    ("₹69,999", True, "normal price"),
    ("Rs. 1,299", True, "Rs prefix"),
    ("₹1,00,000", True, "lakh grouping"),
    ("Out of stock", False, "no number at all"),
    ("", False, "empty price"),
    ("₹0", False, "zero price"),
    ("Call for price", False, "prose"),
]
for price, expect_button, label in CASES:
    reset()
    MOCK["shopping_results"] = [item("Some mobile phone", price)]
    body = client.post("/category/mobiles", data={"search": "some"}).get_data(as_text=True)
    has = 'data-action="open-alert"' in body
    check("%s -> alert button %s" % (label, "shown" if expect_button else "absent"),
          has == expect_button, "price=%r" % price)

reset()
MOCK["shopping_results"] = [item("A phone", "₹69,999")]
body = client.post("/category/mobiles", data={"search": "a"}).get_data(as_text=True)
vals = re.findall(r'data-price="([^"]*)"', body)
check("price_value is a plain number the JS can parse",
      all(re.match(r"^\d+(\.\d+)?$", v) for v in vals), str(vals))
check("no raw currency symbol leaks into the data attribute",
      all("₹" not in v and "," not in v for v in vals))

# ===========================================================================
print("\n" + "=" * 76)
print("2. Shared partials render on every page that needs them")
print("=" * 76)

PAGES = ["/", "/category/mobiles", "/category/laptops", "/category/medicine",
         "/food/", "/food/mcdonalds", "/food/mcdonalds/maharaja-mac"]
for p in PAGES:
    reset()
    MOCK["shopping_results"] = [item("A mobile phone", "₹9,999")]
    r = client.get(p, follow_redirects=True)
    body = r.get_data(as_text=True)
    ok = r.status_code == 200 and "Traceback" not in body and "{{" not in body
    check("%s renders cleanly" % p, ok, "HTTP %s" % r.status_code)
    check("%s carries the install control" % p, 'id="install-btn"' in body)

for p in ("/", "/category/mobiles"):
    reset()
    body = client.get(p, follow_redirects=True).get_data(as_text=True)
    check("%s has the alerts panel and modal" % p,
          'id="alerts-panel"' in body and 'id="alert-modal"' in body)

reset()
home = client.get("/").get_data(as_text=True)
check("only the home page carries the install card",
      'id="install-card"' in home and
      'id="install-card"' not in client.get("/category/mobiles").get_data(as_text=True))

# ===========================================================================
print("\n" + "=" * 76)
print("3. Alert flow end to end (server side of it)")
print("=" * 76)

reset()
MOCK["shopping_results"] = [
    item("Apple iPhone 16 128GB", "₹69,999", "Flipkart", "https://www.flipkart.com/x"),
    item("Apple iPhone 16 128GB", "₹71,900", "Amazon.in", "https://www.amazon.in/x"),
]
search_page = client.post("/", data={"product_query": "iphone 16"}).get_data(as_text=True)
btn = re.search(r'<button class="alertbtn"[^>]*>', search_page)
check("search results expose an alert button", btn is not None)
if btn:
    attrs = btn.group(0)
    check("alert button carries the product title", "data-title=" in attrs)
    check("alert button carries the BEST price, not the dearest",
          'data-price="69999.0"' in attrs, attrs[:120])

# price-check drives the background refresh for saved alerts
reset()
MOCK["shopping_results"] = [item("Apple iPhone 16", "₹69,999")]
data = client.get("/api/price-check", query_string={"title": "Apple iPhone 16"}).get_json()
check("price-check returns a number the alert loop can compare",
      isinstance(data.get("current_price"), (int, float)), str(data))
check("price-check link is safe to open",
      str(data.get("link", "")).startswith("http"))

# ===========================================================================
print("\n" + "=" * 76)
print("4. Status pill and install markup")
print("=" * 76)

reset()
home = client.get("/").get_data(as_text=True)
check("status pill wraps the dot and the label",
      '<span class="dot" aria-hidden="true"></span><span class="label">' in home)
check("dot is hidden from screen readers", 'class="dot" aria-hidden="true"' in home)
check("pill has a background so the dot has an edge to sit against",
      re.search(r"\.eyebrow\{[^}]*background:var\(--green-soft\)", home) is not None)
check("halo animation replaced the hard blink",
      "@keyframes live" in home and "animation:pulse 2s infinite" not in home)

card = client.get("/").get_data(as_text=True)
check("install card explains why, not just what",
      "works offline" in card and "no account" in card.lower())
check("install card offers a quiet decline",
      'data-action="dismiss-install"' in card and "Not now" in card)
check("install card is not fixed to the viewport",
      "position:fixed" not in re.search(r"#install-card\{[^}]*\}", card).group(0))

# ===========================================================================
print("\n" + "=" * 76)
print("5. Everything still renders with hostile listing data")
print("=" * 76)

NASTY = [
    ("<script>alert(1)</script>", "script tag in title"),
    ('" onload="alert(1)', "attribute breakout in title"),
    ("{{ 7*7 }}", "jinja expression in title"),
    ("A" * 3000, "3000-char title"),
    ("🛒" * 200, "emoji flood"),
    ("‮evil", "right-to-left override"),
]
for title, label in NASTY:
    reset()
    MOCK["shopping_results"] = [item(title + " mobile", "₹1,999")]
    try:
        r = client.post("/category/mobiles", data={"search": "x"})
        body = r.get_data(as_text=True)
        ok = (r.status_code == 200 and "<script>alert(1)</script>" not in body
              and 'onload="alert(1)"' not in body and "49" not in body.split("data-title")[0][-40:])
        check("survives %s" % label, ok, "HTTP %s" % r.status_code)
    except Exception as e:
        check("survives %s" % label, False, "%s: %s" % (type(e).__name__, e))

# ===========================================================================
print("\n" + "=" * 76)
bugs = [r for r in RESULTS if not r[1]]
print("SUMMARY: %d checks, %d passed, %d FAILED" %
      (len(RESULTS), len(RESULTS) - len(bugs), len(bugs)))
print("=" * 76)
if bugs:
    for name, _, detail in bugs:
        print("  %s %s" % (name, ("— " + detail) if detail else ""))
    sys.exit(1)
print("No bugs found.")
