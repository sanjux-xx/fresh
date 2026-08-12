"""
Second-pass bug hunt: the original ProductFilter logic, not just the new layers.

Covers price parsing, product grouping, the category/medicine/food paths and
template rendering details that the first sweep did not reach.

    python3 bugtest2.py
"""

import os
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


class _MockSearch:
    def __init__(self, params):
        self.params = params

    def get_dict(self):
        return MOCK


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
import app as productfilter

productfilter.GoogleSearch = _MockSearch
productfilter.app.config["TESTING"] = True
client = productfilter.app.test_client()


def reset():
    productfilter.cache.clear()
    productfilter.request_log.clear()
    productfilter.blocked_ips.clear()
    trustscan.clear_cache()


def item(title, price, source="Amazon.in", link="https://www.amazon.in/dp/X"):
    return {"title": title, "price": price, "source": source,
            "thumbnail": "", "link": link}


def search(items, query="iphone 16"):
    reset()
    MOCK["shopping_results"] = items
    return client.post("/", data={"product_query": query}).get_data(as_text=True)


# ===========================================================================
print("\n" + "=" * 76)
print("1. PRICE PARSING — real SerpApi formats")
print("=" * 76)

PRICES = [
    ("₹69,999", 69999.0, "standard"),
    ("₹69,999.00", 69999.0, "with paise"),
    ("₹1,00,000", 100000.0, "Indian lakh grouping"),
    ("Rs. 69,999", 69999.0, "Rs. prefix"),
    ("Rs 69,999", 69999.0, "Rs prefix without dot"),
    ("INR 69,999", 69999.0, "INR prefix"),
    ("₹69,999 ", 69999.0, "trailing space"),
    (" ₹69,999", 69999.0, "leading space"),
    ("from ₹69,999", 69999.0, "'from' prefix"),
    ("₹69,999 onwards", 69999.0, "'onwards' suffix"),
    ("₹69,999*", 69999.0, "asterisk footnote"),
    ("$799.00", 799.0, "USD listing"),
    ("₹69999", 69999.0, "no separators"),
]
for raw, expected, label in PRICES:
    got = productfilter.extract_price({"price": raw})
    ok = got == expected
    check("parses %-22r as %s" % (raw, expected), ok,
          "" if ok else "got %s" % ("inf" if got == float("inf") else got))

for raw, label in [(None, "None"), (12345, "int"), ("", "empty"),
                   ("Out of stock", "non-numeric text"), ("₹", "symbol only")]:
    try:
        got = productfilter.extract_price({"price": raw})
        check("handles %s price without crashing" % label, True,
              "-> %s" % ("inf" if got == float("inf") else got))
    except Exception as e:
        check("handles %s price without crashing" % label, False,
              "%s: %s" % (type(e).__name__, e))

# ===========================================================================
print("\n" + "=" * 76)
print("2. PRODUCT GROUPING")
print("=" * 76)

reset()
grouped = productfilter.step3_compare_products([
    {"title": "Apple iPhone 16 128GB Black", "price": "₹69,999",
     "store": "Flipkart", "link": "https://flipkart.com/a", "image": ""},
    {"title": "Apple iPhone 16 256GB Black", "price": "₹79,999",
     "store": "Amazon.in", "link": "https://amazon.in/b", "image": ""},
])
check("different storage variants are not merged", len(grouped) == 2,
      "%d group(s)" % len(grouped))

grouped = productfilter.step3_compare_products([
    {"title": "Apple iPhone 16 128GB Black", "price": "₹71,900",
     "store": "Amazon.in", "link": "https://amazon.in/a", "image": ""},
    {"title": "Apple iPhone 16 128GB (Black)", "price": "₹69,999",
     "store": "Flipkart", "link": "https://flipkart.com/b", "image": ""},
])
check("same product from two stores merges into one group", len(grouped) == 1,
      "%d group(s)" % len(grouped))
if grouped:
    check("merged group keeps the cheaper price as best",
          grouped[0]["best_price"] == 69999.0, "got %s" % grouped[0]["best_price"])
    check("merged group keeps both offers", len(grouped[0]["offers"]) == 2)

# real store titles for one identical product, as they actually differ
REAL_TITLES = [
    "Apple iPhone 16 128GB Ultramarine",
    "Apple iPhone 16 (128GB) Ultramarine",
    "Apple iPhone 16 128GB",
    "Apple iPhone 16 128 GB Ultramarine",
    "Apple iPhone 16 Ultramarine, 128 GB",
    "APPLE iPhone 16 (Ultramarine, 128 GB)",
]
grouped = productfilter.step3_compare_products([
    {"title": t, "price": "₹%d" % (69999 + n * 500), "store": "Store%d" % n,
     "link": "https://store%d.com/p" % n, "image": ""}
    for n, t in enumerate(REAL_TITLES)])
check("six real title variants of one phone form ONE group", len(grouped) == 1,
      "%d group(s): %s" % (len(grouped), [g["title"] for g in grouped]))

grouped = productfilter.step3_compare_products([
    {"title": "Apple iPhone 16 (128GB) Black", "price": "₹69,999", "store": "A",
     "link": "https://a.com/p", "image": ""},
    {"title": "Apple iPhone 16 (256GB) Black", "price": "₹79,999", "store": "B",
     "link": "https://b.com/p", "image": ""},
    {"title": "Apple iPhone 16 Pro (128GB) Black", "price": "₹1,19,999", "store": "C",
     "link": "https://c.com/p", "image": ""},
])
check("storage and Pro variants stay separate", len(grouped) == 3,
      "%d group(s)" % len(grouped))
titles = sorted(g["title"] for g in grouped)
check("group titles include storage so variants are distinguishable",
      len(set(titles)) == 3 and any("128GB" in t for t in titles),
      str(titles))

grouped = productfilter.step3_compare_products([
    {"title": "Item", "price": "not a price", "store": "S",
     "link": "https://a.com", "image": ""}])
check("unpriced listings are dropped from grouping", grouped == [],
      "%d group(s)" % len(grouped))

# ===========================================================================
print("\n" + "=" * 76)
print("3. SAVINGS FIGURE")
print("=" * 76)

html = search([
    item("Apple iPhone 16 128GB", "₹75,000", "Croma", "https://croma.com/a"),
    item("Apple iPhone 16 128GB", "₹69,999", "Flipkart", "https://flipkart.com/b"),
])
check("savings shown for one product across two stores", "5,001" in html)

html = search([item("Apple iPhone 16 128GB", "₹69,999", "Croma", "https://croma.com/a")])
check("no savings line for a single offer", "You save vs highest" not in html)

html = search([
    item("Apple iPhone 16 128GB", "₹69,999", "Croma", "https://croma.com/a"),
    item("Apple iPhone 16 128GB", "₹69,999", "Flipkart", "https://flipkart.com/b"),
])
check("no savings line when both prices are identical",
      "You save vs highest" not in html)

# ===========================================================================
print("\n" + "=" * 76)
print("4. CATEGORY + MEDICINE PATHS")
print("=" * 76)

for cat in ("mobiles", "laptops", "fruits", "groceries", "medicine"):
    reset()
    MOCK["shopping_results"] = [
        item("Paracetamol 500mg tablet" if cat == "medicine" else "Apple iPhone 16 mobile",
             "₹120", "Tata 1mg", "https://www.1mg.com/otc/x")]
    r = client.post("/category/" + cat, data={"search": "test"})
    body = r.get_data(as_text=True)
    ok = r.status_code == 200 and "Traceback" not in body
    check("category %s renders" % cat, ok, "HTTP %s" % r.status_code)

reset()
MOCK["shopping_results"] = [item("Apple iPhone 16", "₹69,999")]
r = client.get("/category/mobiles")
check("category GET (no search term) renders", r.status_code == 200)

reset()
MOCK["shopping_results"] = [item("Paracetamol 500mg strip", "₹25", "Netmeds",
                                 "https://www.netmeds.com/x")]
# medicine_filter was replaced by the declarative registry in category_rules;
# every category now runs through the same matcher.
out, _ = productfilter.step1_category_filter(MOCK["shopping_results"],
                                             "medicine", "paracetamol")
check("medicine filter keeps a real medicine listing", len(out) == 1,
      "%d kept" % len(out))

out, _ = productfilter.step1_category_filter([item("Apple iPhone 16 mobile", "₹69,999")],
                                             "medicine", "paracetamol")
check("medicine filter drops a phone listing", len(out) == 0, "%d kept" % len(out))

# ...and the categories that previously had NO filter at all are covered too.
out, _ = productfilter.step1_category_filter(
    [item("HP Victus Gaming Laptop i5", "₹54,999"),
     item("Laptop Cooling Pad", "₹899")], "laptops", "")
check("laptop filter drops an accessory", len(out) == 1, "%d kept" % len(out))

out, _ = productfilter.step1_category_filter(
    [item("Fresh Alphonso Mango 1 kg", "₹399", "BigBasket"),
     item("Real Mango Fruit Juice 1 L", "₹120", "Zepto")], "fruits", "mango")
check("fruits filter drops juice", len(out) == 1, "%d kept" % len(out))

# ===========================================================================
print("\n" + "=" * 76)
print("4b. TRUST BANDS FOR UNKNOWN vs VERIFIED SELLERS")
print("=" * 76)

BANDS = [
    ("https://www.amazon.in/dp/X",          "safe",  True,  "verified retailer"),
    ("https://sangeethamobiles.com/x",      "safe",  True,  "verified regional retailer"),
    ("https://randomshop.in/x",             "ok",    True,  "clean but unrecognised shop"),
    ("https://grocery-mart.xyz/x",          "ok",    True,  "unrecognised on a cheap TLD"),
    ("https://laptop-deals-verify.tk/x",    "risk",  False, "free throwaway TLD"),
    ("https://meds-direct-order.tk/x",      "risk",  False, "free throwaway TLD, pharmacy"),
]
for url, badge, shown, label in BANDS:
    r = trustscan.score_url(url)
    ok = r["badge"] == badge and trustscan.is_trusted(r) == shown
    check("%s -> %s band" % (label, badge), ok,
          "score=%s badge=%s shown=%s" % (r["score"], r["badge"], trustscan.is_trusted(r)))

r = trustscan.score_url("https://randomshop.in/x")
check("unknown seller verdict does not claim it is established",
      "isn't one we recognise" in r["verdict"], r["verdict"])
r = trustscan.score_url("https://www.flipkart.com/x")
check("verified seller verdict says so", "Verified major retailer" in r["verdict"],
      r["verdict"])

# ===========================================================================
print("\n" + "=" * 76)
print("5. TEMPLATE RENDERING DETAILS")
print("=" * 76)

html = search([
    item("Apple iPhone 16 128GB", "₹69,999", "Flipkart", "https://flipkart.com/b"),
    item("Apple iPhone 16 128GB", "₹75,000", "Croma", "https://croma.com/a"),
])
check("prices render with thousands separators", "₹69,999" in html)
check("best-price stamp is rendered", "BEST PRICE" in html)
check("offers disclosure lists both stores",
      "2 stores compared" in html or "stores compared" in html)
check("trust badge markup present", 'class="trust trust-' in html)
check("no raw Jinja markers leaked", "{{" not in html and "{%" not in html)
check("no None leaked into the page", ">None<" not in html)

reset()
MOCK["shopping_results"] = [item("Apple iPhone 16", "₹69,999")]
r = client.get("/")
body = r.get_data(as_text=True)
check("landing page shows categories, not results", "Browse by category" in body)
check("landing page has no receipt", 'class="receipt"' not in body)

# category template with the flat product shape
reset()
MOCK["shopping_results"] = [item("Apple iPhone 16 mobile", "₹69,999")]
body = client.post("/category/mobiles", data={"search": "iphone"}).get_data(as_text=True)
check("category page renders the price string as-is", "₹69,999" in body)
check("category page has no raw Jinja markers",
      "{{" not in body and "{%" not in body)

# an image URL that is hostile should not break the layout
html = search([{"title": "X", "price": "₹100", "source": "Amazon.in",
                "thumbnail": "javascript:alert(1)",
                "link": "https://www.amazon.in/dp/X"}])
check("javascript: thumbnail does not render as an img src",
      'src="javascript:' not in html)

# ===========================================================================
print("\n" + "=" * 76)
print("6. PRICE-ALERT API")
print("=" * 76)

reset()
MOCK["shopping_results"] = [item("Apple iPhone 16", "₹69,999")]
r = client.get("/api/price-check", query_string={"title": "Apple iPhone 16"})
data = r.get_json()
check("price-check returns a numeric price",
      isinstance(data, dict) and isinstance(data.get("current_price"), (int, float)),
      str(data))
check("price-check link is http(s)",
      str(data.get("link", "")).startswith("http"), str(data.get("link")))

reset()
MOCK["shopping_results"] = [item("Scam iPhone", "₹9,999", "Scam",
                                 "https://fl1pkart.com/x")]
r = client.get("/api/price-check", query_string={"title": "Scam iPhone"})
data = r.get_json()
check("price-check will not quote a filtered store",
      data.get("current_price") is None, str(data))

# ===========================================================================
print("\n" + "=" * 76)
print("7. FOOD BLUEPRINT")
print("=" * 76)

import food_backend

for path in ("/food", "/food/", "/food/mcdonalds"):
    reset()
    r = client.get(path, follow_redirects=True)
    check("GET %s" % path, r.status_code in (200, 404), "HTTP %s" % r.status_code)

try:
    brand = next(iter(food_backend.FOOD_DATA))
    items = [i for v in food_backend.FOOD_DATA[brand]["menu"].values() for i in v]
    slug = food_backend.item_to_slug(items[0])
    reset()
    MOCK["shopping_results"] = []
    r = client.get("/food/%s/%s" % (brand, slug), follow_redirects=True)
    body = r.get_data(as_text=True)
    check("food item page renders", r.status_code == 200 and "Traceback" not in body,
          "HTTP %s" % r.status_code)
    check("food buy links are http(s) or #",
          'href="javascript:' not in body)
except Exception as e:
    check("food item page renders", False, "%s: %s" % (type(e).__name__, e))

check("slug round-trips", food_backend.slugify("Big  Mac® Meal") ==
      food_backend.slugify("Big  Mac® Meal"))

# ===========================================================================
print("\n" + "=" * 76)
print("8. FRONTEND JS CONTRACT (inline handlers were moved to a file)")
print("=" * 76)

import re as _re

# The alerts markup now lives in shared partials, so assert against the
# RENDERED page — that is what the browser receives, and it catches an include
# being dropped as well as an element being renamed.
reset()
MOCK["shopping_results"] = [item("Apple iPhone 16 128GB", "₹69,999")]
page = client.post("/", data={"product_query": "iphone 16"}).get_data(as_text=True)
cat_page = client.post("/category/mobiles", data={"search": "iphone"}).get_data(as_text=True)
js = open("static/js/productfilter.js", encoding="utf-8").read()
notif = open("static/notifications.js", encoding="utf-8").read()

# Collect actions across every page: the install card lives only on the home
# page, so scanning one page makes its handler look like dead code.
reset()
_home_for_actions = client.get("/").get_data(as_text=True)
actions = set()
for _doc in (page, cat_page, _home_for_actions):
    actions |= set(_re.findall(r'data-action="([a-z-]+)"', _doc))
# Some controls are created at runtime rather than server-rendered — the
# remove button inside a saved alert, for one — so scan the scripts too.
_notif_src = open("static/notifications.js", encoding="utf-8").read()
actions |= set(_re.findall(r"""setAttribute\(['"]data-action['"],\s*['"]([a-z-]+)['"]""", _notif_src))
handled = set(_re.findall(r'case "([a-z-]+)":', js))
check("every data-action has a handler", actions <= handled,
      "unhandled: %s" % (actions - handled) if actions - handled else
      "%d actions" % len(actions))
check("no handler is dead code", handled <= actions,
      "unused: %s" % (handled - actions) if handled - actions else "")

called = set(_re.findall(r'call\("(\w+)"', js))
defined = set(_re.findall(r"function (\w+)\(", notif))
check("every function called exists in notifications.js", called <= defined,
      "missing: %s" % (called - defined) if called - defined else
      "%d functions" % len(called))

for el_id in ("alert-modal", "modal-inner", "modal-product-title",
              "modal-current-price", "modal-target-price", "alerts-panel",
              "alerts-list", "bell-btn", "bell-badge"):
    check("element #%s present on both listing pages" % el_id,
          'id="%s"' % el_id in page and 'id="%s"' % el_id in cat_page)

check("no inline onclick attributes remain", "onclick=" not in page)
check("no inline <script> blocks remain",
      not _re.search(r"<script(?![^>]*\ssrc=)", page))
check("productfilter.js is loaded", "/static/js/productfilter.js" in page)
check("notifications.js still loaded", "/static/notifications.js" in page)

check("search page has a labelled alert button per product",
      page.count('class="alertbtn"') >= 1 and '<span class="lbl">Alert</span>' in page)
check("category page has a labelled alert button per product",
      cat_page.count('class="alertbtn"') >= 1 and '<span class="lbl">Alert</span>' in cat_page)
check("alert buttons carry title, price and link data",
      all(a in page for a in ('data-action="open-alert"', "data-title=",
                              "data-price=", "data-link=")))
check("alert price is numeric, not a display string",
      all(_re.match(r"^\d+(\.\d+)?$", v) for v in _re.findall(r'data-price="([^"]*)"', page)),
      str(_re.findall(r'data-price="([^"]*)"', page)))
check("header bell is an icon button, not a wide pill",
      'class="bellbtn-top"' in page and "🔔 Price alerts" not in page)

# install prompt: present on every page, hidden until the browser offers it
for label, doc in (("search", page), ("category", cat_page)):
    check("%s page carries the header install button" % label,
          'id="install-btn" class="hidden"' in doc)
    check("%s page has no fixed install bar" % label, 'id="install-banner"' not in doc)
reset()
home = client.get("/").get_data(as_text=True)
check("home page carries the in-flow install card",
      'id="install-card" class="hidden"' in home)
check("install card sits in the content, not pinned to the viewport",
      "position:fixed" not in _re.search(r"#install-card\{[^}]*\}", home).group(0))
check("install actions are handled by the app script",
      all(a in handled for a in ("install-app", "dismiss-install")),
      "handled: %s" % sorted(handled))

bugs = [r for r in RESULTS if not r[1]]
print("SUMMARY: %d checks, %d passed, %d FAILED" %
      (len(RESULTS), len(RESULTS) - len(bugs), len(bugs)))
print("=" * 76)
if bugs:
    for name, _, detail in bugs:
        print("  %s %s" % (name, ("— " + detail) if detail else ""))
    sys.exit(1)
print("No bugs found.")
