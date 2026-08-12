from flask import Flask, render_template, request
from serpapi import GoogleSearch
import re
import os
import ipaddress
import time
import logging
from collections import defaultdict


TRUSTED_STORES = [
    # E-commerce
    "amazon", "flipkart",
    "tatacliq", "vijaysales",
    "myntra", "meesho",
    "snapdeal", "shopsy",

    # Electronics
    "croma", "reliance digital",
    "vijay sales", "ezone",

    # Quick commerce
    "blinkit", "zepto",
    "swiggy instamart", "dunzo",
    "bigbasket", "jiomart",
    "instamart",

    # Pharmacy
    "1mg", "netmeds", "pharmeasy",
    "apollo pharmacy", "medplus",

    # Fashion
    "ajio", "nykaa", "nykaafashion",

    # Other
    "boat", "noise", "samsung shop",
    "apple", "mi store", "oneplus",
]

# ===============================
# SENTRY
# ===============================
import sentry_sdk
from sentry_sdk.integrations.flask import FlaskIntegration

sentry_sdk.init(
    dsn=os.getenv("SENTRY_DSN"),
    integrations=[FlaskIntegration()],
    traces_sample_rate=0.2,
    send_default_pii=False
)

# ===============================
# TRUSTSCAN + AI
# ===============================
import trustscan
import ai_helper

# ===============================
# CATEGORY RULES
# ===============================
# One declarative registry (category_rules.py) decides what belongs in each
# category, for both /category/<name> and the homepage search.
import category_rules

# ===============================
# FOOD BACKEND
# ===============================
from food_backend import food_bp

# ===============================
# APP
# ===============================
app = Flask(__name__)

app.register_blueprint(food_bp)

# Defence in depth for templates: |safe_url renders only plain http(s)
# addresses and collapses anything else (javascript:, data:, file:) to "#".
app.jinja_env.filters["safe_url"] = trustscan.safe_link

# ===============================
# SECURITY / RATE LIMIT
# ===============================
RATE_LIMIT = 50
WINDOW_SIZE = 60
BLOCK_TIME = 2 * 60
CACHE_TTL = 20 * 60

# Deep trust mode also pulls RDAP domain age + DNS per unique domain. Results
# are cached 24h per domain, but the first lookup costs ~1s, so it is off by
# default. Set TRUSTSCAN_DEEP=1 to enable.
DEEP_TRUST = os.getenv("TRUSTSCAN_DEEP", "0") in ("1", "true", "True")

# /api/trust?deep=1 makes the server perform RDAP + DNS lookups against third
# parties on behalf of an anonymous caller. That turns a debug endpoint into a
# small amplifier aimed at rdap.org, so the public parameter is ignored unless
# the operator explicitly opts in. Server-side deep mode (TRUSTSCAN_DEEP above)
# is unaffected — it only runs for domains that appear in real search results.
PUBLIC_DEEP = os.getenv("TRUSTSCAN_PUBLIC_DEEP", "0") in ("1", "true", "True")

request_log = defaultdict(list)
blocked_ips = {}
cache = {}
query_counter = defaultdict(list)

# Hard ceilings. Without these, a stream of unique queries (or unique source
# IPs) grows these dicts until the process runs out of memory — a cheap
# remote denial of service.
MAX_CACHE_ENTRIES = int(os.getenv("MAX_CACHE_ENTRIES", "500"))
MAX_TRACKED_IPS = int(os.getenv("MAX_TRACKED_IPS", "10000"))


def _prune_cache():
    """Drop the oldest entries once the price cache exceeds its ceiling."""
    if len(cache) <= MAX_CACHE_ENTRIES:
        return
    for key in sorted(cache, key=lambda k: cache[k][1])[:len(cache) - MAX_CACHE_ENTRIES]:
        cache.pop(key, None)


def _prune_ip_tables(now):
    """Forget IPs with no recent activity, and cap the tables outright."""
    for ip in [k for k, v in blocked_ips.items() if v < now]:
        blocked_ips.pop(ip, None)
    if len(request_log) > MAX_TRACKED_IPS:
        stale = [ip for ip, hits in request_log.items()
                 if not hits or now - hits[-1] > WINDOW_SIZE]
        for ip in stale:
            request_log.pop(ip, None)
        if len(request_log) > MAX_TRACKED_IPS:
            request_log.clear()
    if len(blocked_ips) > MAX_TRACKED_IPS:
        blocked_ips.clear()


# ===============================
# LOGGING
# ===============================
logging.basicConfig(level=logging.INFO)


# ===============================
# HELPERS
# ===============================
# Proxy headers are attacker-controlled unless a trusted proxy sets them. If
# the app is served directly, honouring CF-Connecting-IP lets anyone reset
# their own rate-limit bucket by sending a new value on every request. Set
# TRUST_PROXY_HEADERS=1 only when Cloudflare (or an equivalent proxy that
# overwrites the header) sits in front of the app.
TRUST_PROXY_HEADERS = os.getenv("TRUST_PROXY_HEADERS", "0") in ("1", "true", "True")

# Cloudflare's published edge ranges (cloudflare.com/ips). With
# TRUST_PROXY_HEADERS=1 the old code believed CF-Connecting-IP from ANY peer,
# so a direct request to the origin could carry a fresh header value per
# request and never hit the rate limit at all — the limiter was decorative for
# anyone who bothered. The header is now honoured only when the connection
# actually arrives from a Cloudflare edge address; traffic that reaches the
# origin directly is limited by its real remote_addr.
CLOUDFLARE_RANGES = (
    "173.245.48.0/20", "103.21.244.0/22", "103.22.200.0/22", "103.31.4.0/22",
    "141.101.64.0/18", "108.162.192.0/18", "190.93.240.0/20", "188.114.96.0/20",
    "197.234.240.0/22", "198.41.128.0/17", "162.158.0.0/15", "104.16.0.0/13",
    "104.24.0.0/14", "172.64.0.0/13", "131.0.72.0/22",
    "2400:cb00::/32", "2606:4700::/32", "2803:f800::/32", "2405:b500::/32",
    "2405:8100::/32", "2a06:98c0::/29", "2c0f:f248::/32",
)

# Extra CIDRs for a non-Cloudflare proxy (comma-separated), e.g. an nginx or
# load balancer in front of the app.
_extra = [c.strip() for c in os.getenv("TRUSTED_PROXY_CIDRS", "").split(",") if c.strip()]

_TRUSTED_PROXY_NETS = []
for _cidr in list(CLOUDFLARE_RANGES) + _extra:
    try:
        _TRUSTED_PROXY_NETS.append(ipaddress.ip_network(_cidr))
    except ValueError:
        logging.warning("Ignoring invalid proxy CIDR: %s", _cidr)


def _peer_is_trusted_proxy(addr):
    if not addr:
        return False
    try:
        ip = ipaddress.ip_address(addr)
    except ValueError:
        return False
    return any(ip in net for net in _TRUSTED_PROXY_NETS)


def get_client_ip():
    peer = request.remote_addr or ""
    if TRUST_PROXY_HEADERS and _peer_is_trusted_proxy(peer):
        fwd = request.headers.get("CF-Connecting-IP")
        if fwd:
            candidate = fwd.split(",")[0].strip()[:45]
            try:
                ipaddress.ip_address(candidate)   # ignore junk / spoofed labels
                return candidate
            except ValueError:
                pass
    return peer or "unknown"

# SerpApi returns prices in many shapes: "₹69,999", "Rs. 69,999", "INR 69999",
# "from ₹69,999", "₹69,999 onwards", "₹69,999*", "$799.00". The old parser
# only understood the first one and silently dropped every other listing
# (price of inf is filtered out downstream), so real offers disappeared.
_PRICE_RE = re.compile(r"(\d[\d,\u00a0\s]*(?:\.\d{1,2})?)")


def extract_price(p):
    """Best-effort numeric price. Returns inf when there is no usable number."""
    raw = p.get("price", "") if isinstance(p, dict) else p
    if isinstance(raw, (int, float)):
        return float(raw) if raw > 0 else float("inf")
    if not isinstance(raw, str):
        return float("inf")

    m = _PRICE_RE.search(raw)
    if not m:
        return float("inf")

    num = re.sub(r"[,\u00a0\s]", "", m.group(1))
    try:
        val = float(num)
    except ValueError:
        return float("inf")
    return val if val > 0 else float("inf")

MIN_QUERY_LEN = 3
MAX_QUERY_LEN = 100


def is_valid_query(q):
    if not q:
        return False
    q = q.strip()
    return MIN_QUERY_LEN <= len(q) <= MAX_QUERY_LEN


# ===============================
# STEP 1 – CATEGORY FILTER
# ===============================
# The old step1_strict_filter only understood phones, and ended with
# `return filtered if filtered else products` — so whenever it removed
# everything it handed back the unfiltered list and the filter did nothing.
# Both problems are gone: category_rules covers every category, and an empty
# result stays empty.


def step1_category_filter(products, slug, term=""):
    """Keep only listings that belong in `slug`. Returns (kept, removed)."""
    return category_rules.filter_products(products, slug, term)


# ===============================
# STEP 2 – VARIANT GROUPING
# ===============================
def step2_group_variants(products):
    for p in products:
        title = p.get("title", "").lower()

        if "pro max" in title:
            p["variant"] = "Pro Max"
        elif "pro" in title and "pro max" not in title:
            p["variant"] = "Pro"
        elif "mini" in title:
            p["variant"] = "Mini"
        else:
            p["variant"] = "Base"

    return products


# ===============================
# STEP 3 – COMPARE & PICK BEST PRICE
# ===============================
def normalize_title(title):
    """Lowercase, strip punctuation, and normalise how specs are written.

    Two details matter for grouping. Parenthesised text is UNWRAPPED rather
    than deleted — stores write "iPhone 16 (128GB)" and throwing that away
    loses the storage size, which is the thing that distinguishes variants.
    And "128 GB" is joined to "128gb" so the same spec written two ways
    produces the same token.
    """
    t = (title or "").lower()
    t = t.replace("(", " ").replace(")", " ").replace("[", " ").replace("]", " ")
    t = re.sub(r"[^a-z0-9\s]", " ", t)
    t = re.sub(r"\s+", " ", t).strip()
    # "128 gb" -> "128gb", "6 . 7 inch" -> "6.7inch"
    t = re.sub(r"\b(\d+)\s+(gb|tb|mb|mah|inch|hz|w)\b", r"\1\2", t)
    return t


# Words that describe the same product differently across stores. Leaving them
# in the grouping key meant "iPhone 16 128GB Black" and "iPhone 16 128GB
# (Black)" became two separate products — so the offers list, the store
# comparison and the savings figure all silently stopped working.
_GROUPING_NOISE = {
    "new", "latest", "original", "genuine", "official", "sealed", "unlocked",
    "with", "and", "for", "the", "in", "of", "buy", "online", "best", "price",
    "offer", "deal", "sale", "free", "delivery", "combo", "pack", "set",
    "black", "white", "blue", "green", "red", "pink", "purple", "yellow",
    "silver", "gold", "grey", "gray", "titanium", "midnight", "starlight",
    "graphite", "natural", "desert", "ultramarine", "teal", "space",
    "smartphone", "mobile", "phone", "cellphone", "handset", "laptop",
    "edition", "variant", "model", "colour", "color",
}
# Tokens that genuinely distinguish products and must survive: storage sizes,
# RAM, model numbers, screen sizes.
_SPEC_RE = re.compile(r"^\d+(gb|tb|mb|mah|inch|in|hz|w)?$")


def build_product_key(p):
    """Canonical identity for a product, stable across store title variations."""
    title = normalize_title(p.get("title", ""))
    tokens = [t for t in title.split() if t and t not in _GROUPING_NOISE]

    if not tokens:
        return normalize_title(p.get("title", ""))[:40]

    # Specs (128gb, 8gb, 6.7inch) always count; otherwise keep the first few
    # descriptive words, which is where the brand and model live.
    specs = sorted({t for t in tokens if _SPEC_RE.match(t)})
    words = [t for t in tokens if not _SPEC_RE.match(t)][:4]
    return " ".join(words + specs)


def clean_display_title(p):
    """A short, human label for a group of offers.

    Must include the storage size: two groups that differ only by capacity
    were both rendering as plain "iPhone 16", so the results page showed what
    looked like the same phone twice at two different prices.
    """
    raw = p.get("title", "") or ""
    title = normalize_title(raw)

    m = re.search(r"iphone\s*(\d+)", title)
    if not m:
        return raw

    model = m.group(1)

    if "pro max" in title:
        variant = "Pro Max"
    elif "pro" in title:
        variant = "Pro"
    elif "plus" in title:
        variant = "Plus"
    elif "mini" in title:
        variant = "Mini"
    else:
        variant = ""

    cap = re.search(r"\b(\d+)\s*(tb|gb)\b", title)
    storage = ("%s%s" % (cap.group(1), cap.group(2).upper())) if cap else ""

    return " ".join(x for x in ["iPhone", model, variant, storage] if x)


def step3_compare_products(products):
    grouped = {}

    for p in products:
        key = build_product_key(p)
        price = extract_price(p)

        if price == float("inf"):
            continue

        if key not in grouped:
            grouped[key] = {
                "title": clean_display_title(p),
                "variant": p.get("variant", "Base"),
                "best_price": price,
                "best_store": p.get("store", ""),
                "best_link": p.get("link", ""),
                "image": p.get("image", ""),
                "offers": []
            }

        grouped[key]["offers"].append({
            "store": p.get("store", ""),
            "price": price,
            "link": p.get("link", ""),
        })

    for product in grouped.values():
        preferred = []
        others = []

        for offer in product["offers"]:
            store_name = offer["store"].lower()
            if any(ts in store_name for ts in TRUSTED_STORES):
                preferred.append(offer)
            else:
                others.append(offer)

        preferred.sort(key=lambda x: x["price"])
        others.sort(key=lambda x: x["price"])

        product["offers"] = preferred + others

        if product["offers"]:
            best = product["offers"][0]
            product["best_price"] = best["price"]
            product["best_store"] = best["store"]
            product["best_link"] = best["link"]
            

    return list(grouped.values())


# ===============================
# TRUSTSCAN FILTERING
# ===============================
# Every merchant link is scored 0-100 by trustscan.py before it reaches a
# template. Anything scoring at or below TRUSTSCAN_MIN_SCORE (default 50) is
# removed from the page; the count of removed listings is passed through so
# the template can show "N low-trust listings hidden" instead of a silently
# short page.

def _score_listings(listings):
    """Score a flat list of dicts that each carry `link` and `store`.

    Returns the same list with a `trust` dict attached to every item. Runs the
    AI tie-break on borderline domains and asks for plain-English verdicts,
    both of which no-op when no AI key is configured.
    """
    if not trustscan.ENABLED or not listings:
        return listings

    scored = trustscan.score_urls(
        [{"url": l.get("link", ""), "store": l.get("store", "")} for l in listings],
        deep=DEEP_TRUST,
    )
    results = list(scored.values())

    try:
        ai_helper.tiebreak(results)
        ai_helper.verdicts_for(results)
    except Exception as e:
        sentry_sdk.capture_exception(e)

    for l in listings:
        t = scored.get(l.get("link", "")) or {}
        # verdict falls back to the heuristic sentence when AI is off
        t.setdefault("verdict", trustscan.default_verdict(t))
        l["trust"] = t
    return listings


def _hidden_summary(dropped):
    """Collapse dropped listings into one row per store, for the notice."""
    seen = {}
    for d in dropped:
        t = d.get("trust") or {}
        name = d.get("store") or t.get("domain") or "Unknown store"
        if name in seen:
            continue
        seen[name] = {
            "store": name,
            "domain": t.get("domain", ""),
            "score": t.get("score"),
            "risk": t.get("risk", "Unknown"),
            "reason": (t.get("flags") or [t.get("verdict", "Below the trust threshold")])[0],
        }
    return sorted(seen.values(), key=lambda x: (x["score"] is None, x["score"]))


def apply_trust_flat(products):
    """Filter a flat product list. Returns (kept, hidden_summary)."""
    if not trustscan.ENABLED or not products:
        return products, []
    _score_listings(products)
    kept, dropped = [], []
    for p in products:
        (kept if trustscan.is_trusted(p.get("trust")) else dropped).append(p)
    return kept, _hidden_summary(dropped)


def apply_trust_grouped(products):
    """Filter offers inside grouped products. Returns (kept, hidden_summary).

    An offer scoring at or below the threshold is dropped. A product whose
    offers are all dropped disappears entirely. Surviving products get their
    best price recomputed from what is left.
    """
    if not trustscan.ENABLED or not products:
        return products, []

    all_offers = [o for p in products for o in p.get("offers", [])]
    _score_listings(all_offers)

    kept_products = []
    dropped = []

    for p in products:
        good, bad = [], []
        for o in p.get("offers", []):
            (good if trustscan.is_trusted(o.get("trust")) else bad).append(o)

        dropped.extend(bad)
        if not good:
            continue

        p["offers"] = good
        p["hidden_offers"] = len(bad)
        best = good[0]
        p["best_price"] = best["price"]
        p["best_store"] = best["store"]
        p["best_link"] = best["link"]
        p["trust"] = best.get("trust", {})
        kept_products.append(p)

    return kept_products, _hidden_summary(dropped)


# ===============================
# SERPAPI
# ===============================
def get_product_prices(query, scope=""):
    # The cache key carries the scope (category slug) as well as the query.
    # Two categories can legitimately build the same query string, and without
    # the scope the first one to run would serve its feed to the other.
    cache_key = "%s|%s" % ((scope or "").lower().strip(), query.lower().strip())
    now = time.time()

    if cache_key in cache:
        data, ts = cache[cache_key]
        if now - ts < CACHE_TTL:
            return data

    params = {
        "engine":   "google_shopping",
        "q":        query,
        "location": "India",
        "hl":       "en",
        "gl":       "in",
        "api_key":  os.getenv("SERPAPI_KEY")
    }

    try:
        results = GoogleSearch(params).get_dict()
        products = []

        for item in results.get("shopping_results", []):
            title = item.get("title", "")
            link  = (
                item.get("link")
                or item.get("product_link")
                or "https://www.google.com/search?tbm=shop&q=" + re.sub(r"\s+", "+", title)
            )

            # Sanitise the scheme HERE, at the point the feed enters the app,
            # rather than relying on the trust filter downstream. TrustScan is
            # switchable (TRUSTSCAN_ENABLED=0) and did not run for
            # /api/price-check, so a `javascript:` link from the upstream feed
            # could reach the JSON API and, through sw.js, a notification
            # target. safe_link collapses anything that is not plain http(s).
            link = trustscan.safe_link(link)
            if link == "#":
                continue

            products.append({
                "title": title,
                "price": item.get("price", ""),
                "store": item.get("source", ""),
                "image": item.get("thumbnail", ""),
                "link":  link
            })

        cache[cache_key] = (products, now)
        _prune_cache()
        return products

    except Exception as e:
        sentry_sdk.capture_exception(e)
        return []

# ===============================
# BLOCK PAGE HTML TEMPLATES
# ===============================
# These pages used to pull Tailwind from a CDN and run an inline countdown
# script. Both are forbidden by this app's own Content-Security-Policy
# (script-src 'self', no external script hosts), which is attached to every
# response including these — so a rate-limited visitor got an unstyled page
# with a frozen timer. They are now self-contained: inline <style> only
# (style-src permits inline), no JavaScript, and the wait is stated in text.
# The Retry-After header is what well-behaved clients actually read.

def _render_block_page(icon, heading, message, seconds, accent):
    mins, secs = seconds // 60, seconds % 60
    wait = ("%dm %02ds" % (mins, secs)) if mins else ("%ds" % secs)
    html = f"""<!DOCTYPE html>
<html lang="en">
<head>
  <meta charset="UTF-8"/>
  <meta name="viewport" content="width=device-width,initial-scale=1"/>
  <meta http-equiv="refresh" content="{seconds}"/>
  <title>Too many requests — ProductFilter</title>
  <style>
    *{{margin:0;padding:0;box-sizing:border-box}}
    body{{background:#0b0f0c;color:#e8e6df;min-height:100vh;display:flex;
      align-items:center;justify-content:center;padding:24px;
      font-family:system-ui,-apple-system,"Segoe UI",sans-serif;line-height:1.55}}
    .card{{text-align:center;max-width:420px}}
    .icon{{font-size:3.5rem;margin-bottom:20px}}
    h1{{font-size:1.75rem;font-weight:800;letter-spacing:-.02em;margin-bottom:10px}}
    p{{color:#9aa39b;margin-bottom:22px}}
    .wait{{background:#141a15;border:1px solid #26302a;border-radius:16px;
      padding:18px 28px;margin-bottom:22px}}
    .wait b{{display:block;font-size:2rem;color:{accent};
      font-variant-numeric:tabular-nums}}
    .wait span{{font-size:.75rem;color:#6f776f;text-transform:uppercase;
      letter-spacing:.08em}}
    .foot{{color:#5d655e;font-size:.75rem}}
  </style>
</head>
<body>
  <div class="card">
    <div class="icon">{icon}</div>
    <h1>{heading}</h1>
    <p>{message}</p>
    <div class="wait"><b>{wait}</b><span>this page reloads itself</span></div>
    <p class="foot">ProductFilter limits requests per minute so the service stays up for everyone.</p>
  </div>
</body>
</html>"""
    return html, 429, {"Retry-After": str(seconds)}


def render_already_blocked_page(retry_after):
    return _render_block_page(
        "⏳", "Slow down",
        "You have made too many requests. Access resumes automatically in:",
        max(1, int(retry_after)), "#f0a020")


def render_newly_blocked_page():
    return _render_block_page(
        "🚫", "Too many requests",
        "You have been paused for a couple of minutes. Access resumes in:",
        BLOCK_TIME, "#e2604a")


# ===============================
# RATE LIMITING — FIXED
# ===============================
@app.before_request
def rate_limit():
    # Skip rate limiting for health check and static files
    if request.path == "/health":
        return None
    if request.path.startswith("/static"):
        return None

    ip = get_client_ip()
    now = time.time()
    _prune_ip_tables(now)

    # Check if IP is currently blocked
    if ip in blocked_ips:
        blocked_until = blocked_ips[ip]
        if now < blocked_until:
            retry_after = int(blocked_until - now)
            logging.warning(f"Blocked IP tried again: {ip}")
            return render_already_blocked_page(retry_after)  # ← RETURN here
        else:
            # Block expired — clear it
            del blocked_ips[ip]
            request_log[ip] = []

    # Clean old requests outside the window
    request_log[ip] = [t for t in request_log[ip] if now - t < WINDOW_SIZE]

    # Check if over limit — FIXED: return is now INSIDE this if block
    if len(request_log[ip]) >= RATE_LIMIT:
        blocked_ips[ip] = now + BLOCK_TIME
        logging.warning(f"IP blocked for exceeding rate limit: {ip}")
        return render_newly_blocked_page()  # ← RETURN inside if block

    # Only reached if NOT blocked — log request and allow
    request_log[ip].append(now)
    return None


# ===============================
# ROUTES
# ===============================
@app.route("/", methods=["GET", "POST"])
def index():
    products = []
    variants = None
    query = ""
    hidden = []
    searched = False

    if request.method == "POST":
        raw_query = request.form.get("product_query", "").strip()
        query = raw_query
        searched = True

        if is_valid_query(query):
            # AI tidies messy input before it reaches SerpApi; returns the
            # original string unchanged when no AI key is set.
            search_query = ai_helper.clean_query(query)

            # The homepage is a general search, so the category is inferred
            # from the query. detect_category only fires on unambiguous terms
            # ("iphone", "atta", "syrup"); a vague query matches nothing and
            # is left unfiltered rather than being filtered by a wrong guess.
            slug = category_rules.detect_category(search_query)

            raw = get_product_prices(search_query, scope=slug or "")

            if slug:
                filtered, _ = step1_category_filter(raw, slug, search_query)
                # A homepage search promises results for what was typed, not
                # for a category the shopper never chose. If the inferred
                # category rejects everything, the guess was wrong — show the
                # raw results rather than an empty page. Category PAGES, which
                # do promise a category, keep the strict empty result.
                if not filtered:
                    filtered = raw
            else:
                filtered = raw

            variants = step2_group_variants(filtered)
            products = step3_compare_products(variants)
            products, hidden = apply_trust_grouped(products)
            products = sorted(products, key=lambda x: x["best_price"])

    return render_template(
        "index.html",
        products=products,
        variants=variants,
        query=query,
        searched=searched,
        hidden=hidden,
        min_score=trustscan.MIN_SCORE,
        savings=compute_savings(products)
    )


def compute_savings(products):
    """What the shopper saves by taking the cheapest listing over the dearest.

    Measured across the offers for the cheapest product, because identical
    listings from different stores collapse into a single product — comparing
    across products would compare different items, which is meaningless.
    Falls back to comparing best prices when there is only one offer each.
    """
    def _clean(vals):
        return [v for v in vals
                if isinstance(v, (int, float)) and v not in (float("inf"),) and v > 0]

    if not products:
        return None

    cheapest = min(
        products,
        key=lambda p: p.get("best_price") if isinstance(p.get("best_price"), (int, float))
        else float("inf"),
    )
    prices = _clean([o.get("price") for o in cheapest.get("offers", [])])

    if len(prices) < 2:
        prices = _clean([p.get("best_price") for p in products])

    if len(prices) < 2:
        return None
    diff = max(prices) - min(prices)
    return "{:,.0f}".format(diff) if diff > 0 else None


# The old medicine_filter lived here. It was the only category with real
# filtering, and its rules are now rows in category_rules.CATEGORIES
# ("medicine"), applied by the same code path as every other category.


# ===============================
# CATEGORY ROUTE
# ===============================
@app.route("/category/<category_name>", methods=["GET", "POST"])
def category_page(category_name):
    cat = category_rules.get(category_name)

    if cat is None:
        return render_template(
            "category.html",
            category=category_name,
            products=[],
            hidden=[],
            searched=False,
            off_category=0,
            min_score=trustscan.MIN_SCORE,
        )

    search_term = (request.form.get("search", "").strip()
                   if request.method == "POST" else "")

    # The homepage has always enforced is_valid_query() (3-100 characters);
    # this route enforced nothing, so a 5,000-character term went straight into
    # a billable SerpApi call and a cache entry. Every distinct term is a fresh
    # paid request, which made this the cheapest way to burn the API quota.
    if search_term and not is_valid_query(search_term):
        search_term = search_term[:MAX_QUERY_LEN].strip()
        if len(search_term) < MIN_QUERY_LEN:
            search_term = ""

    # Each category owns its SerpApi phrasing, so "fruits" asks for
    # "fresh mango fruit buy online India" instead of "mango fresh fruits".
    final_query = cat.build_query(search_term)

    products = get_product_prices(final_query, scope=cat.slug)

    # THE FIX: every category is filtered against its own rules, and the
    # shopper's search term, before anything else runs. Nothing falls back to
    # the unfiltered feed.
    products, off_category = step1_category_filter(products, cat.slug, search_term)

    if cat.slug == "mobiles":
        products = step2_group_variants(products)

    products, hidden = apply_trust_flat(products)
    products = sorted(products, key=extract_price)

    # The alert button needs a number, but SerpApi hands us a display string
    # ("₹68,999"). Attach the parsed value so the template can pass it straight
    # to the alerts JS; listings we cannot price simply get no alert button.
    for p in products:
        value = extract_price(p)
        p["price_value"] = None if value == float("inf") else value

    return render_template(
        "category.html",
        category=category_name,
        products=products,
        query=search_term,
        hidden=hidden,
        searched=request.method == "POST",
        off_category=off_category,
        min_score=trustscan.MIN_SCORE,
    )


# ===============================
# API ROUTE
# ===============================
@app.route("/api/price-check")
def price_check():
    title = request.args.get("title", "").strip()
    # Same bounds as every other entry point. An unbounded title was a free
    # cache-miss generator, and each miss is a billable SerpApi call.
    if not is_valid_query(title):
        return {"error": "Invalid query"}, 400

    products = get_product_prices(title)
    if not products:
        return {"current_price": None, "link": None}

    def safe_price(p):
        try:
            return float(p.get("price", "").replace("₹", "").replace(",", ""))
        except:
            return float("inf")

    # price alerts must not quote a price from a store we refuse to show
    products, _ = apply_trust_flat(products)
    if not products:
        return {"current_price": None, "link": None}

    products_sorted = sorted(products, key=safe_price)
    best = products_sorted[0]

    try:
        price = float(best.get("price", "").replace("₹", "").replace(",", ""))
    except:
        price = None

    # Belt and braces: this link is handed to sw.js, which uses it as a
    # notification target, so it must be a plain http(s) address even if the
    # trust layer above is switched off.
    link = trustscan.safe_link(best.get("link", ""))

    return {
        "current_price": price,
        "link": link if link != "#" else None,
        "store": best.get("store", "")
    }


# ===============================
# TRUSTSCAN DEBUG API
# ===============================
@app.route("/api/trust")
def api_trust():
    """Score any URL on demand:  /api/trust?url=example.com&deep=1

    Handy for checking why a store was hidden from results.
    """
    url = request.args.get("url", "").strip()
    if not url:
        return {"error": "missing url parameter"}, 400

    asked_deep = request.args.get("deep") in ("1", "true", "yes")
    deep = asked_deep and PUBLIC_DEEP
    res = trustscan.score_url(url, store=request.args.get("store", ""), deep=deep)
    if res:
        try:
            ai_helper.tiebreak([res])
            ai_helper.verdicts_for([res])
        except Exception:
            pass
        res["shown_on_site"] = trustscan.is_trusted(res)
        res["threshold"] = trustscan.MIN_SCORE
        if asked_deep and not deep:
            res["note"] = ("deep mode is disabled for public callers; "
                           "set TRUSTSCAN_PUBLIC_DEEP=1 to allow it")
    return res or {"error": "could not score"}, 200


@app.route("/api/trust-status")
def api_trust_status():
    """Config + AI quota visibility, so you can see the layer is alive."""
    return {
        "trustscan": {
            "enabled": trustscan.ENABLED,
            "min_score": trustscan.MIN_SCORE,
            "deep_mode": DEEP_TRUST,
            "public_deep": PUBLIC_DEEP,
            "feeds_enabled": trustscan.FEEDS_ENABLED,
            "safe_browsing_key": bool(os.getenv("GOOGLE_SAFE_BROWSING_KEY")),
        },
        "ai": ai_helper.stats(),
    }


# ===============================
# HEALTH CHECK
# ===============================
@app.route("/health")
def health():
    return {"status": "ok"}

@app.route("/sw.js")
def sw():
    return app.send_static_file("sw.js")

@app.route("/manifest.json")
def manifest():
    return app.send_static_file("manifest.json")

# ===============================
# SECURITY HEADERS
# ===============================
@app.after_request
def add_headers(resp):
    resp.headers["X-Frame-Options"] = "DENY"
    resp.headers["X-Content-Type-Options"] = "nosniff"
    resp.headers["Referrer-Policy"] = "strict-origin-when-cross-origin"
    resp.headers["Permissions-Policy"] = "geolocation=(), microphone=(), camera=(), interest-cohort=()"
    resp.headers["Cross-Origin-Opener-Policy"] = "same-origin"

    # Only meaningful over TLS, and only safe to send when the site is
    # actually HTTPS-only. Enabled by default in production.
    if os.getenv("ENABLE_HSTS", "1") in ("1", "true", "True"):
        resp.headers["Strict-Transport-Security"] = "max-age=31536000; includeSubDomains"

    # script-src is strict: no 'unsafe-inline', no external script hosts. All
    # page behaviour lives in /static/js/productfilter.js, so an injected <script>
    # or onclick simply will not execute.
    #
    # style-src still needs 'unsafe-inline' because the templates carry inline
    # <style> blocks and per-row style attributes. Style injection is a far
    # weaker primitive than script execution, and img-src stays open because
    # product thumbnails come from arbitrary retailer CDNs.
    resp.headers["Content-Security-Policy"] = (
        "default-src 'self'; "
        "img-src 'self' data: https:; "
        "style-src 'self' 'unsafe-inline' https://fonts.googleapis.com; "
        "font-src 'self' https://fonts.gstatic.com; "
        "script-src 'self'; "
        "connect-src 'self'; "
        "form-action 'self'; "
        "frame-ancestors 'none'; "
        "base-uri 'self'; "
        "object-src 'none'"
    )
    return resp