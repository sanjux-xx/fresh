"""Did the merchant-link change actually land? Run this after copying files.

    python3 verify_install.py

No API key, no network, no dependencies beyond the app's own. It checks that
every moving part of the change is present and wired together, renders a real
search page against a fake SerpApi payload, and reports the first thing that
is missing rather than a wall of output.

Written because a partial copy is silent: if app.py keeps the |buy_url filter
but loses the resolver, every page still renders 200 OK and every Buy button
quietly points back at Google. That is the failure this script exists to
catch.
"""
import os
import re
import sys
import types

HERE = os.path.dirname(os.path.abspath(__file__))
os.chdir(HERE)
sys.path.insert(0, HERE)

OK, BAD = [], []


def ok(msg):
    OK.append(msg)
    print("  \033[32mOK\033[0m   %s" % msg)


def bad(msg, fix):
    BAD.append((msg, fix))
    print("  \033[31mMISS\033[0m %s\n       -> %s" % (msg, fix))


def read(rel):
    try:
        with open(os.path.join(HERE, rel), encoding="utf-8") as fh:
            return fh.read()
    except FileNotFoundError:
        return None


print("=" * 72)
print("1. IS THE ENGINE IN app.py?")
print("=" * 72)

src = read("app.py")
if src is None:
    print("app.py not found — run this from inside the productfilter folder.")
    sys.exit(1)

PARTS = [
    ("merchant_routes", "the route table",
     "the whole MERCHANT LINK RESOLUTION section is missing"),
    ("def remember_merchant_route", "remember_merchant_route()",
     "copy the MERCHANT LINK RESOLUTION section from source/app.py"),
    ("def resolve_merchant_link", "resolve_merchant_link()",
     "copy the MERCHANT LINK RESOLUTION section from source/app.py"),
    ("def _pick_store", "_pick_store()",
     "copy the MERCHANT LINK RESOLUTION section from source/app.py"),
    ("def _prefer_https", "_prefer_https()  (the Flipkart/Myntra fix)",
     "copy the MERCHANT LINK RESOLUTION section from source/app.py"),
    ("def go_to_merchant", "the /go/<product_id> route",
     "copy the MERCHANT REDIRECT section from source/app.py"),
    ("immersive_product_page_token", "the token capture in get_product_prices",
     "get_product_prices must read immersive_product_page_token from each row"),
    ("def buy_url", "the |buy_url template filter",
     "copy buy_url() and its jinja_env.filters registration"),
    ('filters["buy_url"]', "the |buy_url filter registration",
     'add app.jinja_env.filters["buy_url"] = buy_url'),
]
for needle, label, fix in PARTS:
    (ok if needle in src else lambda m, f=fix: bad(m, f))("%s present" % label)

# Only flag it as a *sent parameter*. Reading item.get("direct_link") in the
# link fallback chain is fine and stays — the dead thing is the request key.
if re.search(r'"direct_link"\s*:\s*"?true"?', src):
    bad("direct_link is STILL being sent to SerpApi",
        "remove the \"direct_link\": \"true\" line from get_product_prices — "
        "it is not a real parameter and does nothing")
else:
    ok("the dead direct_link parameter is gone")

print()
print("=" * 72)
print("2. ARE THE TEMPLATES WIRED UP?")
print("=" * 72)

for rel, needles in (("templates/index.html", ["product.best_go", "offer.go_link"]),
                     ("templates/category.html", ["p.go_link"])):
    body = read(rel)
    if body is None:
        bad("%s not found" % rel, "check the path")
        continue
    for n in needles:
        if n in body and "buy_url" in body:
            ok("%s uses %s|buy_url" % (rel, n))
        else:
            bad("%s does not use %s with |buy_url" % (rel, n),
                "copy the line from source/%s" % rel)

# Characters that get lost when copying out of a PDF.
idx = read("templates/index.html") or ""
cat = read("templates/category.html") or ""
if "</a>>" in idx:
    bad("index.html has a stray '>' after </a>  (PDF copy artifact)",
        "find '</a>>' and delete the extra '>'")
else:
    ok("no stray '>' in index.html")
if re.search(r'class="buy"[^>]*>View\s*<', cat):
    bad("category.html lost the arrow: 'View' should be 'View →'",
        "restore the → character in the View button")
else:
    ok("category.html View button looks intact")

print()
print("=" * 72)
print("3. DOES A REAL SEARCH PAGE PRODUCE /go LINKS?")
print("=" * 72)

os.environ.setdefault("SERPAPI_KEY", "verify-only")
os.environ.setdefault("TRUSTSCAN_ENABLED", "0")

ROW = {
    "title": "Apple iPhone 15 128GB", "product_id": "13867141147044777971",
    "product_link": "https://www.google.com/search?ibp=oshop&q=iphone",
    "immersive_product_page_token": "FAKE-TOKEN", "source": "Amazon.in",
    "price": "₹41,980", "extracted_price": 41980.0,
    "thumbnail": "https://example.com/t.jpg",
}
STORES = {"product_results": {"stores": [
    {"name": "Amazon.in", "extracted_price": 41980.0,
     "link": "https://www.amazon.in/dp/TEST123"}]}}


class FakeSearch:
    def __init__(self, params):
        self.params = params

    def get_dict(self):
        if self.params.get("engine") == "google_immersive_product":
            return STORES
        return {"shopping_results": [ROW]}


if "serpapi" not in sys.modules:
    m = types.ModuleType("serpapi")
    m.GoogleSearch = FakeSearch
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

try:
    import app as pf
    pf.GoogleSearch = FakeSearch
    pf.app.config["TESTING"] = True
    client = pf.app.test_client()

    page = client.post("/", data={"product_query": "iphone 15"})
    body = page.get_data(as_text=True)
    n_go = len(re.findall(r'href="/go/\d+', body))
    if page.status_code != 200:
        bad("home search returned HTTP %s" % page.status_code,
            "see the traceback in your server log")
    elif n_go:
        ok("home search rendered %d /go link(s)" % n_go)
    else:
        bad("home search rendered NO /go links (Buy still points at Google)",
            "get_product_prices is not setting go_link — the resolver "
            "section did not get copied")

    cat_body = client.get("/category/mobiles").get_data(as_text=True)
    if re.search(r"/go/\d+", cat_body):
        ok("category page rendered /go link(s)")
    else:
        bad("category page rendered NO /go links",
            "same cause as above")

    r = client.get("/go/13867141147044777971")
    if r.status_code == 404:
        bad("/go route does not exist (404)",
            "the MERCHANT REDIRECT section did not get copied")
    elif r.status_code == 302 and "amazon.in" in r.headers.get("Location", ""):
        ok("a click on /go redirects to the merchant (%s)"
           % r.headers["Location"][:48])
    elif r.status_code == 302:
        bad("/go redirected to %s instead of the merchant"
            % r.headers.get("Location", "")[:60],
            "check resolve_merchant_link and _pick_store")
    else:
        bad("/go returned HTTP %s" % r.status_code, "unexpected — check logs")
except Exception as e:
    bad("the app failed to import or render: %s: %s" % (type(e).__name__, e),
        "fix the traceback above before deploying")

print()
print("=" * 72)
if BAD:
    print("RESULT: %d check(s) passed, %d STILL MISSING" % (len(OK), len(BAD)))
    print("=" * 72)
    for msg, fix in BAD:
        print("  - %s\n      %s" % (msg, fix))
    print("\nThe safest fix is to copy source/app.py over your app.py whole,")
    print("rather than re-applying the individual edits.")
    sys.exit(1)
print("RESULT: all %d checks passed — the change is fully in place." % len(OK))
print("=" * 72)
print("Now deploy/restart, then search the live site and click a product.")
print("The address bar should show the merchant's domain, not google.com.")

