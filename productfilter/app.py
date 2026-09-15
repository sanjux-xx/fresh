from flask import Flask, render_template, request, redirect, url_for
from serpapi import GoogleSearch
import requests.exceptions
import hashlib
import hmac
import json
import mimetypes
import re
import os
import ipaddress
import time
import logging
import threading
from collections import defaultdict
from urllib.parse import urlsplit, urlunsplit, quote


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

_SECRET_QS_RE = re.compile(
    r"((?:api_key|serp_api_key|apikey|key|token|access_token|secret|password)"
    r"=)[^&\s\"'<>]+", re.IGNORECASE)
_SECRET_HDR_RE = re.compile(r"(Bearer\s+)[A-Za-z0-9._\-]+", re.IGNORECASE)

def _scrub_text(value):
    if not isinstance(value, str):
        return value
    value = _SECRET_QS_RE.sub(r"\1[REDACTED]", value)
    return _SECRET_HDR_RE.sub(r"\1[REDACTED]", value)

def _scrub_event(node):
    if isinstance(node, dict):
        return {k: _scrub_event(v) for k, v in node.items()}
    if isinstance(node, list):
        return [_scrub_event(v) for v in node]
    if isinstance(node, tuple):
        return tuple(_scrub_event(v) for v in node)
    return _scrub_text(node)

def _before_send(event, hint):
    try:
        return _scrub_event(event)
    except Exception:
        return None

sentry_sdk.init(
    dsn=os.getenv("SENTRY_DSN"),
    integrations=[FlaskIntegration()],
    traces_sample_rate=0.2,
    send_default_pii=False,
    before_send=_before_send,
    before_send_transaction=_before_send,
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


def buy_url(url):
    """|buy_url renders a Buy target: our own /go route, or a plain http(s).

    safe_url exists to collapse anything that is not an absolute http(s)
    address, which is right for feed links but would also collapse the
    relative /go/<id> path this app generates. This filter permits exactly
    that one internal shape — a literal /go/ followed by digits — and hands
    everything else to safe_url unchanged.
    """
    if isinstance(url, str) and re.match(
            r"^/go/[0-9]{1,32}(\?[A-Za-z0-9%._~=&+-]{0,300})?$", url.strip()):
        return url.strip()
    return trustscan.safe_link(url)


app.jinja_env.filters["buy_url"] = buy_url

# ===============================
# STATIC ASSET VERSIONING (speed-test fix 02)
# ===============================
# The speed test found `cache-control: no-cache` on every static asset, with a
# last-modified of 1980-01-01 — a placeholder, not a policy — so a repeat
# visitor re-downloaded the JavaScript, icons and manifest on every navigation.
#
# The fix is the standard pair: a content hash in the URL, and a one-year
# immutable lifetime for any URL that carries one. Change a file and its hash
# changes, so the new URL is a cache miss by construction and there is nothing
# to invalidate. Templates must therefore reference assets through
# {{ static_url('js/productfilter.js') }} rather than a bare /static/... path;
# an unversioned /static/ URL still works, it just gets a modest one-hour TTL.

# Python's mimetypes table predates woff2 on some platforms, and a font served
# as application/octet-stream is a font some proxies decline to compress or
# cache sensibly. Register it explicitly.
mimetypes.add_type("font/woff2", ".woff2")

STATIC_MAX_AGE = int(os.getenv("STATIC_MAX_AGE", str(365 * 24 * 60 * 60)))
STATIC_UNVERSIONED_MAX_AGE = int(os.getenv("STATIC_UNVERSIONED_MAX_AGE", "3600"))

# HTML is not immutable, but it is identical for every visitor (no login, no
# per-user content), so it is safe to let a shared cache hold it briefly and
# keep serving it while it revalidates.
HTML_SMAX_AGE = int(os.getenv("HTML_SMAX_AGE", "120"))
HTML_STALE_WHILE_REVALIDATE = int(os.getenv("HTML_STALE_WHILE_REVALIDATE", "600"))

_static_hashes = {}
_static_hash_lock = threading.Lock()


def static_version(filename):
    """Short content hash of a file under static/, or "" if unreadable.

    Memoised per process: hashing happens once per file per boot, never per
    request. Deploys restart the process, which is exactly when a file's
    content can have changed.
    """
    with _static_hash_lock:
        if filename in _static_hashes:
            return _static_hashes[filename]

    digest = ""
    try:
        path = os.path.join(app.static_folder, filename)
        hasher = hashlib.md5()
        with open(path, "rb") as handle:
            for chunk in iter(lambda: handle.read(65536), b""):
                hasher.update(chunk)
        digest = hasher.hexdigest()[:10]
    except OSError:
        # Missing or unreadable file: fall back to an unversioned URL rather
        # than raising inside a template render.
        logging.warning("static_url: cannot hash %s", filename)

    with _static_hash_lock:
        _static_hashes[filename] = digest
    return digest


@app.template_global()
def static_url(filename):
    """/static/<filename>?v=<hash> — safe to cache immutably for a year."""
    version = static_version(filename)
    if version:
        return url_for("static", filename=filename, v=version)
    return url_for("static", filename=filename)


# ===============================
# SECURITY / RATE LIMIT
# ===============================
RATE_LIMIT = 50
WINDOW_SIZE = 60
BLOCK_TIME = 2 * 60
CACHE_TTL = 20 * 60

# ===============================
# COLD-MISS BUDGET (speed-test fix 01)
# ===============================
# The 2026-08-13 speed test measured warm category hits at ~50 ms and cold
# misses at 3.63 s (/category/medicine) to 11.54 s (/category/fruits) — a 231x
# spread, all of it spent inside the synchronous SerpApi call below. Upstream
# service time once cached is 9 ms, so none of that latency is ours to keep.
#
# Three defences, in order of how often they save a request:
#
#   STALE_TTL       An entry older than CACHE_TTL is stale, not gone. Up to
#                   STALE_TTL it is served immediately and refreshed in the
#                   background (stale-while-revalidate), so an expiring cache
#                   never turns into an 11-second page for the visitor who
#                   happens to arrive first.
#   SERPAPI_TIMEOUT A genuinely uncached query still has to wait, but not
#                   indefinitely. google-search-results defaults its timeout
#                   to 60000 *seconds*, i.e. no timeout at all; this caps the
#                   worst case a shopper can experience.
#
#                   IMPORTANT: this is a hang-guard, not a latency target, and
#                   it MUST sit above SerpApi's normal cold response time. The
#                   speed test measured genuine upstream latency of 3.6-11.5 s
#                   on fresh queries — an earlier value of 6 s cut off healthy
#                   responses mid-flight, which made every uncached search
#                   render an empty page. 30 s clears real upstream latency
#                   with margin while staying under gunicorn's 45 s worker
#                   timeout, so a true hang still dies here, with a fallback,
#                   instead of as a 502.
#   PREWARM         A background thread keeps every category slug warm, so in
#                   normal operation the synchronous path is never taken for
#                   a category landing page at all.
STALE_TTL = int(os.getenv("STALE_TTL", str(24 * 60 * 60)))
SERPAPI_TIMEOUT = max(float(os.getenv("SERPAPI_TIMEOUT", "30")), 15.0)

# Ceiling on concurrent background refreshes. Every refresh is a billable
# SerpApi call, and each gunicorn worker holds its own in-process cache, so
# without a cap a burst of traffic on expiring keys could fan out into a lot
# of paid calls at once.
MAX_REFRESH_THREADS = int(os.getenv("MAX_REFRESH_THREADS", "2"))

# Pre-warming is on by default but no-ops without a SERPAPI_KEY, so local and
# CI runs stay free. Set PREWARM=0 to disable in production.
#
# CREDIT-WASTE FIX (2026-09-15). The pre-warm loop was the single largest
# consumer of the SerpApi quota, and none of what it spent was driven by a
# shopper:
#
#   * It ran in EVERY gunicorn worker. The cache is in-process, so two workers
#     meant two independent loops paying twice for identical feeds.
#   * It ran around the clock. Overnight, when nobody was on the site, it kept
#     paying to keep five feeds warm for nobody — visible on the SerpApi
#     dashboard as a dead-flat floor of successful searches at 02:00-08:00 UTC
#     with zero failures, which is the signature of a cron, not of users.
#   * PREWARM_INTERVAL (900) sat below CACHE_TTL (1200), so every other cycle
#     was a no-op and the real cadence was an unintuitive 1800 s.
#   * It had no spend ceiling of any kind.
#
# Four gates now stand in front of it. Each one is independently switchable so
# a deployment can trade credits for warmth as it likes:
#
#   PREWARM_SINGLE_WORKER  Only one process in the container pre-warms, chosen
#                          by an OS-level lock. Removes the per-worker
#                          multiplier outright.
#   PREWARM_ACTIVE_HOURS   A UTC window outside which cycles are skipped. The
#                          default covers Indian shopping hours and leaves the
#                          dead of night unpaid.
#   PREWARM_DEMAND_WINDOW  A category is only kept warm if somebody actually
#                          visited it recently. A category nobody browses stops
#                          costing anything until it is browsed again.
#   AUTO_CREDIT_DAILY_BUDGET  A hard daily ceiling on every call no shopper is
#                          waiting for (pre-warm + background refresh). When it
#                          is reached the automatic paths stand down for the
#                          rest of the UTC day; user-facing searches are never
#                          blocked by it.
PREWARM = os.getenv("PREWARM", "1") in ("1", "true", "True")
# Clamped to CACHE_TTL: an interval below the freshness window just burns
# cycles that find the entry still fresh and skip, which made the effective
# cadence twice the configured one and impossible to reason about.
PREWARM_INTERVAL = max(int(os.getenv("PREWARM_INTERVAL", str(30 * 60))),
                       CACHE_TTL)
PREWARM_SINGLE_WORKER = os.getenv("PREWARM_SINGLE_WORKER", "1") in (
    "1", "true", "True")
# "HH-HH" in UTC, inclusive of the start hour and exclusive of the end hour.
# Default 03-19 UTC == 08:30-00:30 IST. Set to "0-24" to pre-warm all day.
PREWARM_ACTIVE_HOURS = os.getenv("PREWARM_ACTIVE_HOURS", "3-19")
# Seconds since a category page was last requested, beyond which that category
# is no longer worth paying to keep warm. Set to 0 to warm every category
# unconditionally (the old behaviour).
PREWARM_DEMAND_WINDOW = int(os.getenv("PREWARM_DEMAND_WINDOW", str(6 * 60 * 60)))
# Where workers record "this category was just visited". The pre-warm loop runs
# in one worker but demand arrives at all of them, so last-seen has to be
# shared. A small JSON file under /tmp is enough and needs no new services.
PREWARM_STATE_PATH = os.getenv("PREWARM_STATE_PATH",
                               "/tmp/productfilter-prewarm.json")
PREWARM_LOCK_PATH = os.getenv("PREWARM_LOCK_PATH",
                              "/tmp/productfilter-prewarm.lock")

# Daily ceiling on unattended billable calls. 0 disables the ceiling.
AUTO_CREDIT_DAILY_BUDGET = int(os.getenv("AUTO_CREDIT_DAILY_BUDGET", "150"))

# /api/price-check used to run a fresh billable search per alert title. Titles
# are full product names, so they never matched a cached feed and every check
# was a guaranteed cache miss — one credit per alert, per device, every 30
# minutes, for as long as the alert existed. Alerts are now answered out of the
# category feeds already in cache (the alert was created from one of those
# cards, so the product is in there), and the upstream path is opt-in.
PRICE_CHECK_ALLOW_UPSTREAM = os.getenv("PRICE_CHECK_ALLOW_UPSTREAM", "0") in ("1", "true", "True")

# Optional bearer token guarding /api/credit-usage. Unset means the endpoint
# does not exist — it reports spend, which is nobody's business but yours.
CREDIT_STATS_TOKEN = os.getenv("CREDIT_STATS_TOKEN", "")

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

_state_lock = threading.RLock()


# ===============================
# CREDIT ACCOUNTING (credit-waste fix 2026-09-15)
# ===============================
# Every billable SerpApi call now declares who asked for it. Without this the
# only place spend was visible was the SerpApi dashboard, which reports a total
# per hour and cannot tell a shopper's search apart from a background loop —
# exactly the question that took a code audit to answer.
#
# Sources:
#   user_search       a person typed something or opened a cold page. Legitimate.
#   swr_refresh       a stale feed refreshed behind a real request. Semi-automatic.
#   prewarm           the background loop. Nobody is waiting on this.
#   merchant_resolve  a /go click. One per real click.
#   price_check       a price-alert lookup that had to go upstream.
#
# Counts are per-process and reset at UTC midnight, which is also the window
# the daily budget is measured over.
AUTOMATIC_SOURCES = ("prewarm", "swr_refresh", "price_check")

_credit_lock = threading.Lock()
_credit_counts = defaultdict(int)
_credit_day = None

# Attribution rides on a thread-local rather than on a function argument.
# Pre-warm and background refresh each run on their own thread, so the thread
# *is* the source, and threading it through as a parameter would have changed
# the signature of the fetch function that the test suite replaces with a
# stub — a fix for a billing bug should not break the tests that guard the
# cache. Anything that does not declare itself is a user-facing search, which
# is the safe default: it is never silenced by the unattended budget.
_credit_ctx = threading.local()


def _current_credit_source():
    return getattr(_credit_ctx, "source", "user_search")


class crediting(object):
    """Label every billable call made inside this block.

    Restores the previous label on exit, so nesting (a /go resolve made while
    serving a page, say) cannot leave the wrong source stuck on the thread.
    """

    def __init__(self, source):
        self.source = source
        self.previous = None

    def __enter__(self):
        self.previous = getattr(_credit_ctx, "source", None)
        _credit_ctx.source = self.source
        return self

    def __exit__(self, exc_type, exc, tb):
        if self.previous is None:
            try:
                del _credit_ctx.source
            except AttributeError:
                pass
        else:
            _credit_ctx.source = self.previous
        return False


def _utc_day():
    return time.strftime("%Y-%m-%d", time.gmtime())


def _roll_credit_day_locked():
    global _credit_day
    today = _utc_day()
    if _credit_day != today:
        _credit_day = today
        _credit_counts.clear()


def note_credit(source):
    """Record one billable upstream call against its originating source."""
    with _credit_lock:
        _roll_credit_day_locked()
        _credit_counts[source] += 1


def credit_snapshot():
    """Today's spend, broken down by who caused it."""
    with _credit_lock:
        _roll_credit_day_locked()
        counts = dict(_credit_counts)
    automatic = sum(counts.get(s, 0) for s in AUTOMATIC_SOURCES)
    total = sum(counts.values())
    return {
        "utc_day": _utc_day(),
        "by_source": counts,
        "automatic": automatic,
        "user_driven": total - automatic,
        "total": total,
        "automatic_daily_budget": AUTO_CREDIT_DAILY_BUDGET,
        "automatic_budget_left": (
            max(0, AUTO_CREDIT_DAILY_BUDGET - automatic)
            if AUTO_CREDIT_DAILY_BUDGET > 0 else None),
        "pid": os.getpid(),
    }


def auto_credit_available():
    """False once unattended calls have used up today's budget.

    Only the automatic paths consult this. A shopper waiting on a page is never
    turned away because a background loop spent the quota.
    """
    if AUTO_CREDIT_DAILY_BUDGET <= 0:
        return True
    with _credit_lock:
        _roll_credit_day_locked()
        spent = sum(_credit_counts.get(s, 0) for s in AUTOMATIC_SOURCES)
    return spent < AUTO_CREDIT_DAILY_BUDGET


def _prune_cache():
    with _state_lock:
        if len(cache) <= MAX_CACHE_ENTRIES:
            return
        items = [(k, v[1]) for k, v in list(cache.items())]
        items.sort(key=lambda kv: kv[1])
        for key, _ in items[:len(items) - MAX_CACHE_ENTRIES]:
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

def normalize_feed_link(url):
    """Percent-encode a feed URL that arrives with raw, illegal characters."""
    if not isinstance(url, str):
        return ""
    url = url.strip()
    if not url:
        return ""
    try:
        parts = urlsplit(url)
    except ValueError:
        return ""
    return urlunsplit((
        parts.scheme,
        parts.netloc,
        quote(parts.path, safe="/%:@!$&'()*+,;=~-._"),
        quote(parts.query, safe="/%:@!$&'()*+,;=~-._?"),
        quote(parts.fragment, safe="/%:@!$&'()*+,;=~-._?"),
    ))

MIN_QUERY_LEN = 3
MAX_QUERY_LEN = 100

SERPAPI_NUM = int(os.getenv("SERPAPI_NUM", "60"))
SERPAPI_NUM_FALLBACK = int(os.getenv("SERPAPI_NUM_FALLBACK", "20"))
PRICE_SANITY_RATIO = float(os.getenv("PRICE_SANITY_RATIO", "0.25"))

def drop_implausible_prices(products, price_of=extract_price):
    if len(products) < 4:
        return products, 0

    priced = [(p, price_of(p)) for p in products]
    values = sorted(v for _, v in priced if v not in (None, float("inf")) and v > 0)
    if len(values) < 4:
        return products, 0

    median = values[len(values) // 2]
    floor = median * PRICE_SANITY_RATIO

    kept = [p for p, v in priced
            if v in (None, float("inf")) or v <= 0 or v >= floor]
    return kept, len(products) - len(kept)

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
                # Click target for the Buy button: the /go route that resolves
                # the merchant URL. Falls back to the Google link.
                "best_go": p.get("go_link") or p.get("link", ""),
                "image": p.get("image", ""),
                "offers": []
            }

        grouped[key]["offers"].append({
            "store": p.get("store", ""),
            "price": price,
            "link": p.get("link", ""),
            "go_link": p.get("go_link") or p.get("link", ""),
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
            product["best_go"] = best.get("go_link") or best["link"]
            

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

    results = trustscan.score_many(
    [{"url": l.get("link", ""), "store": l.get("store", "")} for l in listings],
    deep=DEEP_TRUST,
   )
    

    try:
        ai_helper.tiebreak(results)
        ai_helper.verdicts_for(results)
    except Exception as e:
        sentry_sdk.capture_exception(e)

    for l, t in zip(listings, results):
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
        p["best_go"] = best.get("go_link") or best["link"]
        p["trust"] = best.get("trust", {})
        kept_products.append(p)

    return kept_products, _hidden_summary(dropped)


# ===============================
# MERCHANT LINK RESOLUTION
# ===============================
# google_shopping hands back a google.com/search?ibp=oshop link and nothing
# else, so a shopper who clicks lands on Google Shopping rather than on the
# store. Each row does carry an `immersive_product_page_token`, and the
# google_immersive_product engine turns that token into
# `product_results.stores[]`, where every entry has the merchant's own URL.
#
# That second call is a separate billable SerpApi search, so it is made
# lazily: the feed renders with /go/<product_id> links, and the resolve only
# happens when someone actually clicks. One credit per real click, not per
# rendered card.

# product_id -> {token, store, fallback, resolved, resolved_store, ts, hit}
merchant_routes = {}

MAX_MERCHANT_ROUTES = int(os.getenv("MAX_MERCHANT_ROUTES", "5000"))
# Resolved merchant URLs are cached for longer than the price feed: the URL
# of a product page is far more stable than its price, and every cache miss
# costs a credit.
MERCHANT_TTL = int(os.getenv("MERCHANT_TTL", str(6 * 60 * 60)))
# A click is a person waiting on a redirect, so the resolve gets a leash.
# On timeout the shopper goes to the Google link rather than staring at a
# spinner. This has to clear the slowest case that still succeeds: a token
# SerpApi has never fetched before takes several seconds, while a token it
# has cached comes back in under a second. Measured against live traffic, 6s
# was cutting off cold tokens that would have resolved fine. It also has to
# stay under gunicorn's 30s worker timeout, or a slow resolve kills a worker
# instead of falling back.
MERCHANT_TIMEOUT = float(os.getenv("MERCHANT_TIMEOUT", "15"))

# How old the feed behind a /go link may be before its immersive token is
# assumed dead (regression fix, 2026-09-15).
#
# A cache entry carries the `immersive_product_page_token` for every row, and a
# cache hit replays those same tokens (see _reseed_routes). Google's tokens are
# short-lived, so a feed served from cache for hours hands resolve_merchant_link
# a token that no longer works — the resolve returns nothing and the Buy button
# silently degrades to the Google Shopping page instead of the merchant's site.
#
# This was masked for as long as pre-warming re-fetched every feed every ~30
# minutes in every worker: tokens were never old enough to expire. Once
# pre-warming became demand-gated, a visitor in a quiet period could be served a
# feed up to STALE_TTL (24 h) old, and every Buy button on it pointed at Google.
#
# STALE_TTL is about *prices*, which age gracefully — a slightly old price is
# still useful. Tokens do not age gracefully: they either work or they don't.
# They need their own, much shorter bound, which is what this is.
MERCHANT_TOKEN_MAX_AGE = int(os.getenv("MERCHANT_TOKEN_MAX_AGE", "1800"))

PRODUCT_ID_RE = re.compile(r"^[0-9]{1,32}$")
# Crawlers and link previewers must never trigger a resolve.
#
# Every /go click costs a SerpApi credit. Category pages are plain GET pages
# carrying ~80 /go links each, so a single Googlebot pass over /category/mobiles
# would spend ~80 credits, and it would do that for every category, on every
# crawl, silently. Chat apps and browsers that prefetch links are the same
# problem in miniature. Before this change the links pointed at google.com and
# cost nothing to follow, so the crawl budget question simply did not exist.
#
# Bots get the Google Shopping fallback: a working destination, zero credits.
# robots.txt, rel="nofollow" and X-Robots-Tag cover the well-behaved ones;
# this list catches the rest.
BOT_UA_RE = re.compile(
    r"bot|crawler|spider|crawling|slurp|bingpreview|facebookexternalhit|"
    r"whatsapp|telegrambot|slackbot|discordbot|twitterbot|linkedinbot|"
    r"embedly|quora link preview|pinterest|redditbot|applebot|ia_archiver|"
    r"semrush|ahrefs|mj12|dotbot|petalbot|yandex|duckduckbot|headlesschrome|"
    r"python-requests|curl/|wget|go-http-client|axios|okhttp|java/",
    re.IGNORECASE,
)

def _is_automated_client():
    """True for crawlers, previewers and prefetchers — anything but a shopper.

    Also treats an explicit prefetch/prerender hint as automated: the browser
    is guessing, and a guess must not cost a credit.
    """
    ua = request.headers.get("User-Agent", "")
    if not ua or BOT_UA_RE.search(ua):
        return True
    purpose = (
        request.headers.get("Sec-Purpose", "")
        or request.headers.get("Purpose", "")
        or request.headers.get("X-Purpose", "")
    )
    return "prefetch" in purpose.lower() or "preview" in purpose.lower()


def _prune_merchant_routes():
    """Drop the oldest routes once the table exceeds its ceiling.

    Same reasoning as _prune_cache: this dict is keyed by data that an
    anonymous caller can cause to appear, so it needs a hard ceiling or it is
    a slow memory exhaustion bug.
    """
    if len(merchant_routes) <= MAX_MERCHANT_ROUTES:
        return
    doomed = sorted(merchant_routes, key=lambda k: merchant_routes[k]["ts"])
    for key in doomed[:len(merchant_routes) - MAX_MERCHANT_ROUTES]:
        merchant_routes.pop(key, None)


def merchant_route_path(product_id, query="", scope=""):
    """Build the /go path, carrying the query that can rebuild the route.

    This table lives in process memory and gunicorn runs more than one
    worker, so the worker that serves the click is often not the worker that
    served the search and will not know this product_id. Carrying the
    original query means that worker can re-run the (cached) feed search,
    repopulate the table and resolve normally, instead of stranding the
    shopper. Without this, roughly one click in `workers` would dead-end.
    """
    path = "/go/" + product_id
    params = []
    if query:
        params.append("q=" + quote(query[:MAX_QUERY_LEN], safe=""))
    if scope:
        params.append("s=" + quote(scope[:40], safe=""))
    return path + ("?" + "&".join(params) if params else "")


def remember_merchant_route(product_id, token, store, fallback,
                            query="", scope=""):
    """Record how to resolve one listing. Returns the /go path, or "".

    Returns "" when the row cannot be resolved (no id, no token, junk id), so
    the caller keeps using the plain Google link for that listing.
    """
    if not product_id or not token:
        return ""
    product_id = str(product_id).strip()
    if not PRODUCT_ID_RE.match(product_id):
        return ""
    if not isinstance(token, str) or not token.strip():
        return ""

    entry = merchant_routes.get(product_id)
    # Keep an already-resolved URL rather than throwing it away every time
    # the same product reappears in a later feed.
    resolved = entry.get("resolved") if entry else None
    resolved_store = entry.get("resolved_store", "") if entry else ""
    resolved_ts = entry.get("resolved_ts", 0) if entry else 0

    merchant_routes[product_id] = {
        "token": token,
        "store": store or "",
        "fallback": fallback or "",
        "resolved": resolved,
        "resolved_store": resolved_store,
        "resolved_ts": resolved_ts,
        "ts": time.time(),
    }
    _prune_merchant_routes()
    return merchant_route_path(product_id, query, scope)


def _prefer_https(url):
    """Upgrade a merchant URL to https.

    Google hands some merchant links back as plain http — Flipkart and Myntra
    both did in a live audit. TrustScan rightly treats plain HTTP as a red
    flag on a page where someone is about to pay, so those listings scored 38
    and 97 respectively for the same domain depending only on the scheme, and
    two of India's largest retailers were being shown a scam warning. The
    scheme is an artefact of the feed, not a property of the store: the same
    Flipkart URL scores 96 over https.

    Every merchant that reaches this point is a Google Shopping advertiser
    and serves https; an http-only store in 2026 is exactly the kind of site
    the warning is meant for, and it will still be scored on its merits after
    the upgrade.
    """
    if isinstance(url, str) and url.startswith("http://"):
        return "https://" + url[len("http://"):]
    return url


def _pick_store(stores, preferred):
    """Choose which of a product's sellers to send the shopper to.

    Prefers the seller whose name matches the one shown on the card — the
    shopper clicked a specific store at a specific price, and landing on a
    different merchant is a bait and switch. Falls back to the cheapest
    seller that has a usable link, then to the first one.
    """
    usable = []
    for s in stores or []:
        if not isinstance(s, dict):
            continue
        link = trustscan.safe_link(normalize_feed_link(s.get("link", "")))
        if link == "#":
            continue
        usable.append((s, _prefer_https(link)))

    if not usable:
        return None, ""

    want = (preferred or "").strip().lower()
    if want:
        for s, link in usable:
            name = (s.get("name") or "").strip().lower()
            if name and (name == want or name in want or want in name):
                return link, s.get("name") or preferred

    def _price_of(pair):
        s = pair[0]
        for field in ("extracted_price", "extracted_base_price"):
            v = s.get(field)
            if isinstance(v, (int, float)) and v > 0:
                return float(v)
        return extract_price({"price": s.get("price") or s.get("base_price") or ""})

    cheapest = min(usable, key=_price_of)
    return cheapest[1], cheapest[0].get("name") or ""


def resolve_merchant_link(product_id):
    """Turn a remembered listing into (merchant_url, store_name).

    Returns (None, "") when the listing is unknown or cannot be resolved.
    Cached for MERCHANT_TTL so repeat clicks on the same product — the common
    case when a page is shared — cost nothing.
    """
    entry = merchant_routes.get(product_id)
    if not entry:
        return None, ""

    now = time.time()
    if entry.get("resolved") and now - entry.get("resolved_ts", 0) < MERCHANT_TTL:
        return entry["resolved"], entry.get("resolved_store", "")

    params = {
        "engine":     "google_immersive_product",
        "page_token": entry["token"],
        "hl":         "en",
        "gl":         "in",
        "api_key":    os.getenv("SERPAPI_KEY"),
    }

    try:
        note_credit("merchant_resolve")
        search = GoogleSearch(params)
        # The client takes its request timeout as an attribute, not as a
        # params key — a "timeout" inside params_dict would be forwarded to
        # SerpApi as a query parameter and the request would still hang on
        # the library default (60000, passed straight to requests as
        # seconds, i.e. effectively forever). Set defensively: the attribute
        # is what the pinned 2.4.2 client reads, and a client that lacks it
        # simply keeps its own default.
        try:
            search.timeout = MERCHANT_TIMEOUT
        except Exception:
            pass
        data = search.get_dict()
    except Exception as e:
        sentry_sdk.capture_exception(e)
        return None, ""

    if not isinstance(data, dict) or data.get("error"):
        return None, ""

    # Do not trust the shape of the payload. SerpApi has been seen returning
    # unexpected types in these fields, and `product_results` arriving as a
    # list (rather than an object) used to raise AttributeError here, which
    # surfaced to the shopper as a 500 error page instead of the Google
    # fallback. Every branch below must end in a fallback, never an exception.
    product_results = data.get("product_results")
    if not isinstance(product_results, dict):
        return None, ""

    stores = product_results.get("stores")
    if not isinstance(stores, (list, tuple)):
        return None, ""
    link, store_name = _pick_store(stores, entry.get("store"))
    if not link:
        return None, ""

    entry["resolved"] = link
    entry["resolved_store"] = store_name
    entry["resolved_ts"] = now
    return link, store_name


# ===============================
# SERPAPI
# ===============================
# Keys currently being refreshed in the background. A key is single-flighted:
# ten simultaneous visitors to an expiring category trigger one paid refresh,
# not ten, and all ten are served the stale copy without waiting for it.
_refresh_inflight = set()
_refresh_lock = threading.Lock()


def _cache_key_for(query, scope=""):
    # The cache key carries the scope (category slug) as well as the query.
    # Two categories can legitimately build the same query string, and without
    # the scope the first one to run would serve its feed to the other.
    return "%s|%s" % ((scope or "").lower().strip(), query.lower().strip())


def _reseed_routes(entry, query, scope):
    """Re-register the merchant routes carried by a cache entry.

    The route table and the price cache are pruned independently and a /go
    recovery deliberately re-runs the lookup to rebuild routes — if a cache
    hit returned early without re-seeding them, that recovery would find
    nothing and the shopper would bounce to Google.
    """
    for seed in (entry[2] if len(entry) > 2 else []):
        remember_merchant_route(query=query, scope=scope, **seed)


def _remint_tokens(query, scope):
    """Re-fetch a feed to mint fresh merchant tokens. Returns True on success.

    Bypasses the cache deliberately: the cached copy is exactly the thing whose
    tokens have expired, so serving it again would just reproduce the failure.

    This is one billable call, and it only ever happens on a real click whose
    resolve would otherwise have dumped the shopper on Google Shopping. It is
    attributed to the user, not to an automatic source, and it is not subject to
    the unattended budget — a person is waiting on this redirect.
    """
    if not is_valid_query(query):
        return False
    cache_key = _cache_key_for(query, scope)
    try:
        with crediting("user_search"):
            products = _fetch_product_prices(query, scope, cache_key)
    except Exception as exc:
        sentry_sdk.capture_exception(exc)
        return False
    return products is not None


def _claim_refresh(cache_key):
    """True when this caller owns the background refresh for cache_key."""
    with _refresh_lock:
        if cache_key in _refresh_inflight:
            return False
        if len(_refresh_inflight) >= MAX_REFRESH_THREADS:
            return False
        _refresh_inflight.add(cache_key)
        return True


def _release_refresh(cache_key):
    with _refresh_lock:
        _refresh_inflight.discard(cache_key)


def _refresh_in_background(query, scope, cache_key):
    """Refresh a stale entry without making anyone wait for it.

    Declining to start (already in flight, or at the concurrency ceiling) is
    not a failure: the stale copy is still served, and the next request after
    this one finishes will see fresh data.
    """
    # A background refresh is spend nobody is waiting on, so it answers to the
    # daily automatic budget. Declining leaves the stale copy in place, which
    # STALE_TTL already allows for up to 24 h — the shopper sees a page either
    # way, and the feed refreshes on the first request after midnight UTC.
    if not auto_credit_available():
        logging.info("swr-refresh: skipped, automatic daily budget spent")
        return
    if not _claim_refresh(cache_key):
        return

    def run():
        try:
            with crediting("swr_refresh"):
                _fetch_product_prices(query, scope, cache_key)
        except Exception as exc:            # pragma: no cover - defensive
            sentry_sdk.capture_exception(exc)
        finally:
            _release_refresh(cache_key)

    threading.Thread(target=run, name="swr-refresh", daemon=True).start()


def get_product_prices(query, scope=""):
    """Feed for a query, with stale-while-revalidate.

    Fresh  (age < CACHE_TTL)  -> served as-is.
    Stale  (age < STALE_TTL)  -> served immediately, refreshed in background.
    Absent                    -> one synchronous, timeout-bounded fetch.

    Spend made here is attributed to whatever `crediting(...)` block the caller
    is inside, defaulting to a user-facing search.
    """
    cache_key = _cache_key_for(query, scope)
    now = time.time()

    entry = cache.get(cache_key)
    if entry:
        data, ts = entry[0], entry[1]
        _reseed_routes(entry, query, scope)
        age = now - ts
        if age < CACHE_TTL:
            return data
        if data and age < STALE_TTL:
            # THE FIX: an expired entry is stale, not useless. Hand the
            # shopper the copy we already have (~50 ms) and pay for the
            # refresh on a thread nobody is waiting on.
            _refresh_in_background(query, scope, cache_key)
            return data

    products = _fetch_product_prices(query, scope, cache_key)
    if products is None:
        # Upstream failed or timed out. A stale copy, however old, beats an
        # empty page — this is the only path that may exceed STALE_TTL.
        return entry[0] if entry else []
    return products


def _fetch_product_prices(query, scope, cache_key):
    """The billable SerpApi call. Returns products, or None on failure.

    None is distinct from []: an empty list is a feed that genuinely came back
    with nothing, while None means the call failed and the caller should fall
    back to whatever it already had.

    The credit is recorded before the call, not after, so a call that times out
    still shows up as money spent — it is billed either way. See the CREDIT
    ACCOUNTING section for where the source label comes from.
    """
    now = time.time()
    source = _current_credit_source()
    note_credit(source)
    params = {
        "engine":   "google_shopping",
        "q":        query,
        "location": "India",
        "hl":       "en",
        "gl":       "in",
        # NOTE: there is no parameter on this engine that returns the
        # merchant's own URL. `direct_link=true` used to sit here and was
        # silently ignored — google_shopping rows carry no link/direct_link/
        # merchant_link field at all, only `product_link`, which points at
        # google.com/search?ibp=oshop. That is why every Buy button landed on
        # Google Shopping. The merchant URL lives behind a second call, on the
        # google_immersive_product engine, keyed by the per-row
        # immersive_product_page_token captured below and resolved lazily by
        # /go/<product_id> when a shopper actually clicks.
       
        "api_key":  os.getenv("SERPAPI_KEY")
    }

    def _do_search(num):
        """Run one SerpApi call with the given num and return get_dict()."""
        search = GoogleSearch({**params, "num": str(num)})
        # google-search-results passes .timeout straight to requests.get and
        # defaults it to 60000 — seconds, not milliseconds, so effectively no
        # timeout. Without this line a slow upstream can hold a gunicorn
        # thread (and the shopper) far past the 45 s gunicorn timeout.
        search.timeout = SERPAPI_TIMEOUT
        return search.get_dict()
    try:
        try:
            results = _do_search(SERPAPI_NUM)
        except requests.exceptions.ReadTimeout:
            # The full request timed out. Record a breadcrumb (not a full
            # exception) so the retry context is visible in Sentry traces
            # without creating a duplicate issue, then try again with a
            # smaller page size that SerpApi can answer more quickly.
            sentry_sdk.add_breadcrumb(
                message=(
                    f"SerpApi ReadTimeout with num={SERPAPI_NUM}; "
                    f"retrying with num={SERPAPI_NUM_FALLBACK}"
                ),
                category="serpapi",
                level="warning",
                data={"query": query, "scope": scope},
            )
            # The retry is a second billable search, so it is counted as one.
            # Undercounting here is how a retry storm hides inside a quota.
            note_credit(source)
            results = _do_search(SERPAPI_NUM_FALLBACK)
            
        products = []
        # Everything needed to rebuild the merchant routes from a cache hit.
        seeds = []

        for item in results.get("shopping_results", []):
            title = item.get("title", "")
            link  = normalize_feed_link(
                item.get("direct_link")
                or item.get("merchant_link")
                or item.get("link")
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

            store = item.get("source", "")

            # Remember how to reach the real merchant for this row. Returns
            # "" when the row has no usable token or id, in which case the
            # listing keeps its Google link and behaves exactly as before.
            seed = {
                "product_id": item.get("product_id"),
                "token": item.get("immersive_product_page_token"),
                "store": store,
                "fallback": link,
            }
            go_link = remember_merchant_route(query=query, scope=scope, **seed)
            if go_link:
                seeds.append(seed)

            products.append({
                "title": title,
                "price": item.get("price", ""),
                "store": store,
                "image": item.get("thumbnail", ""),
                "link":  link,
                # Where the Buy button should point. Falls back to the Google
                # link when this row cannot be resolved.
                "go_link": go_link or link,
            })

        # Stamped on completion, not on entry: with a 6 s ceiling on the call
        # itself, stamping the start time would age every entry by however
        # long upstream took and shorten the window this feed stays fresh.
        with _state_lock:
            cache[cache_key] = (products, time.time(), seeds)
        _prune_cache()
        return products

    except Exception as e:
        sentry_sdk.capture_exception(e)
        # None, not [] — the caller distinguishes "upstream failed, reuse what
        # you have" from "the feed is genuinely empty".
        return None


# ===============================
# CACHE PRE-WARMING (speed-test fix 01)
# ===============================
# Every category landing page is a known, finite URL, so there is no reason to
# discover its feed on a shopper's request. This keeps all of them inside
# CACHE_TTL, which means the synchronous path above is reserved for genuinely
# novel searches — and even those are now bounded by SERPAPI_TIMEOUT.
#
# COST NOTE (rewritten 2026-09-15 — this loop was the credit leak).
#
# Before: one billable call per category, per gunicorn worker, per cycle,
# forever, with no demand check and no ceiling. At the shipped defaults — 5
# categories, 2 workers, a 900 s interval against a 1200 s freshness window —
# that was ~20 calls an hour, ~480 a day, every day, whether or not a single
# person visited the site. On the SerpApi dashboard it appeared as a flat floor
# of successful searches that never dropped to zero even at 03:00 UTC.
#
# After: one worker pre-warms (PREWARM_SINGLE_WORKER), only inside the active
# window (PREWARM_ACTIVE_HOURS), only for categories somebody actually browsed
# recently (PREWARM_DEMAND_WINDOW), and only while the unattended daily budget
# holds (AUTO_CREDIT_DAILY_BUDGET). An idle site now costs nothing. A busy site
# pays at most one call per browsed category per PREWARM_INTERVAL.
#
# Warmth is not lost when a gate closes: STALE_TTL (24 h) means the first
# visitor to a cold-but-not-ancient category is still served instantly from the
# stale copy while a refresh runs behind them.
_prewarm_started = False
_prewarm_lock_handle = None


# ── Shared demand signal ───────────────────────────────────────────────────
# The loop lives in one worker but requests land on all of them, so "was this
# category visited recently" has to cross process boundaries. A small JSON file
# is sufficient and introduces no new dependency. Failures here are always
# non-fatal: if the state file cannot be read or written, pre-warm falls back
# to treating the category as in demand, i.e. to the old behaviour, rather than
# silently going cold.
def _read_prewarm_state():
    try:
        with open(PREWARM_STATE_PATH, "r") as fh:
            data = json.load(fh)
        return data if isinstance(data, dict) else {}
    except Exception:
        return {}


def note_category_demand(slug):
    """Record that a shopper just asked for this category."""
    if PREWARM_DEMAND_WINDOW <= 0:
        return
    try:
        state = _read_prewarm_state()
        now = time.time()
        # Only write when the stamp is meaningfully old. Without this every
        # request would rewrite the file, which on a busy category turns a
        # cheap read into constant disk churn.
        if now - float(state.get(slug, 0) or 0) < 60:
            return
        state[slug] = now
        tmp = PREWARM_STATE_PATH + ".%d.tmp" % os.getpid()
        with open(tmp, "w") as fh:
            json.dump(state, fh)
        os.replace(tmp, PREWARM_STATE_PATH)     # atomic, no torn reads
    except Exception:
        pass


def _category_in_demand(slug, state):
    """True when this category is worth paying to keep warm."""
    if PREWARM_DEMAND_WINDOW <= 0:
        return True                              # demand gating disabled
    try:
        last = float(state.get(slug, 0) or 0)
    except (TypeError, ValueError):
        return True
    return (time.time() - last) < PREWARM_DEMAND_WINDOW


# ── Active-hours gate ──────────────────────────────────────────────────────
def _parse_active_hours(spec):
    """"3-19" -> (3, 19). Returns (0, 24) — always on — on anything unparseable."""
    try:
        start, end = str(spec).split("-", 1)
        start, end = int(start.strip()), int(end.strip())
        if 0 <= start <= 24 and 0 <= end <= 24 and start != end:
            return start, end
    except Exception:
        pass
    return 0, 24


def _in_active_hours(now=None):
    start, end = _parse_active_hours(PREWARM_ACTIVE_HOURS)
    if (start, end) == (0, 24):
        return True
    hour = time.gmtime(now if now is not None else time.time()).tm_hour
    if start < end:
        return start <= hour < end
    # Window wraps midnight UTC, e.g. "19-3".
    return hour >= start or hour < end


# ── Single-worker gate ─────────────────────────────────────────────────────
def _claim_prewarm_slot():
    """True in exactly one process per host, via an advisory file lock.

    The lock is held for the process lifetime by keeping the handle in a module
    global. A worker that dies releases it automatically — the OS drops the
    lock with the file descriptor — so the next worker to restart picks the job
    up rather than pre-warming stopping for good.

    On any platform without fcntl, or if anything about the lock fails, the
    caller is allowed to proceed. Degrading to the old duplicate-spend
    behaviour is preferable to a deployment whose feeds silently go cold.
    """
    global _prewarm_lock_handle
    if not PREWARM_SINGLE_WORKER:
        return True
    try:
        import fcntl
    except ImportError:
        return True
    try:
        handle = open(PREWARM_LOCK_PATH, "w")
        fcntl.flock(handle.fileno(), fcntl.LOCK_EX | fcntl.LOCK_NB)
    except (OSError, IOError):
        return False                             # another worker owns it
    except Exception:
        return True
    handle.write(str(os.getpid()))
    handle.flush()
    _prewarm_lock_handle = handle                # keep it open == keep the lock
    return True


# ── The loop ───────────────────────────────────────────────────────────────
def _prewarm_once():
    """One pass over the categories. Returns the number of credits spent."""
    if not _in_active_hours():
        return 0

    state = _read_prewarm_state()
    spent = 0

    for slug, cat in category_rules.CATEGORIES.items():
        if not auto_credit_available():
            logging.info("prewarm: stopping cycle, automatic daily budget spent")
            break
        if not _category_in_demand(slug, state):
            continue                             # nobody has browsed it lately
        try:
            query = cat.build_query("")
            cache_key = _cache_key_for(query, slug)
            entry = cache.get(cache_key)
            if entry and time.time() - entry[1] < CACHE_TTL:
                continue                         # still fresh, don't pay again
            with crediting("prewarm"):
                _fetch_product_prices(query, slug, cache_key)
            spent += 1
        except Exception as exc:
            sentry_sdk.capture_exception(exc)

    return spent


def _prewarm_loop():
    while True:
        try:
            _prewarm_once()
        except Exception as exc:                 # pragma: no cover - defensive
            # A loop that dies on one bad cycle stops warming forever and the
            # only symptom is slow pages, so it is swallowed and retried.
            sentry_sdk.capture_exception(exc)
        time.sleep(PREWARM_INTERVAL)


def start_prewarm():
    """Start the pre-warm thread at most once per host.

    No-ops without a SERPAPI_KEY so local runs, tests and CI never reach for a
    paid upstream just by importing the app.
    """
    global _prewarm_started
    if not PREWARM or _prewarm_started:
        return
    if not os.getenv("SERPAPI_KEY"):
        logging.info("prewarm: skipped, no SERPAPI_KEY set")
        return
    if not _claim_prewarm_slot():
        logging.info("prewarm: skipped, another worker holds the pre-warm lock")
        return
    _prewarm_started = True
    threading.Thread(target=_prewarm_loop, name="prewarm", daemon=True).start()
    start, end = _parse_active_hours(PREWARM_ACTIVE_HOURS)
    logging.info(
        "prewarm: started in pid %d, every %ss, %d categories, "
        "active %02d:00-%02d:00 UTC, demand window %ss, daily auto budget %s",
        os.getpid(), PREWARM_INTERVAL, len(category_rules.CATEGORIES),
        start, end, PREWARM_DEMAND_WINDOW,
        AUTO_CREDIT_DAILY_BUDGET or "unlimited")


start_prewarm()

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
            raw, _ = drop_implausible_prices(raw)

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

    # Tell the pre-warm loop this category is alive. Recorded before the feed
    # is fetched, and only for real clients: if a crawler's pass counted as
    # demand, a single Googlebot visit would keep all five categories warm (and
    # billable) for the whole demand window with no shopper involved.
    if not _is_automated_client():
        note_category_demand(cat.slug)

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
    upstream_count = len(products)
    products, implausible = drop_implausible_prices(products)

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
        upstream_count=upstream_count,
        implausible=implausible,
        min_score=trustscan.MIN_SCORE,
    )


# ===============================
# API ROUTE
# ===============================
# ===============================
# MERCHANT REDIRECT
# ===============================
@app.route("/go/<product_id>")
def go_to_merchant(product_id):
    """Send the shopper to the merchant's own product page.

    The listing's merchant URL is resolved here, on click, rather than for
    every card at search time — see the MERCHANT LINK RESOLUTION section for
    why. Three things must hold before we redirect anywhere:

      1. the id is one we handed out (this is not an open redirect — the
         destination comes from our own table, never from the request),
      2. the resolved address is plain http(s), via safe_link,
      3. the merchant clears the trust threshold, checked here because this
         is the first moment the real domain is known.

    Anything that fails falls back to the Google Shopping link the card would
    have used before this change, so a resolve failure degrades to the old
    behaviour instead of a dead end.
    """
    product_id = (product_id or "").strip()
    if not PRODUCT_ID_RE.match(product_id):
        return redirect("/", code=302)

    google_product = "https://www.google.com/shopping/product/" + product_id

    if _is_automated_client():
      return redirect(google_product, code=302)

    recover_q = request.args.get("q", "").strip()
    recover_s = request.args.get("s", "").strip()[:40]
    reminted = False

    entry = merchant_routes.get(product_id)

    if not entry:
        # This worker never served the search that produced the link — see
        # merchant_route_path. Re-run the feed for the query carried on the
        # URL, which is usually a cache hit, and try the table again.
        if is_valid_query(recover_q):
            try:
                get_product_prices(recover_q, scope=recover_s)
            except Exception as e:
                sentry_sdk.capture_exception(e)
            entry = merchant_routes.get(product_id)

    # The token this entry carries may have come from a feed that has been sat
    # in cache for hours. Refresh it *before* spending a resolve on a token that
    # is almost certainly dead — see MERCHANT_TOKEN_MAX_AGE. Skipped when we
    # already hold a resolved URL for this product, which needs no token at all.
    if entry is not None and MERCHANT_TOKEN_MAX_AGE > 0:
        have_fresh_resolution = (
            entry.get("resolved")
            and time.time() - entry.get("resolved_ts", 0) < MERCHANT_TTL)
        token_age = time.time() - entry.get("ts", 0)
        if (not have_fresh_resolution
                and token_age > MERCHANT_TOKEN_MAX_AGE
                and is_valid_query(recover_q)):
            if _remint_tokens(recover_q, recover_s):
                reminted = True
                entry = merchant_routes.get(product_id) or entry

    if not entry:
        # Nothing left to resolve with. Send the shopper to the Google
        # Shopping page for this exact product — the behaviour before this
        # change — rather than dumping them on the homepage.
        return redirect(google_product, code=302)

    fallback = trustscan.safe_link(entry.get("fallback", ""))
    fallback = fallback if fallback != "#" else "/"

    # Belt and braces around the whole resolve. Everything inside is written
    # to return rather than raise, but this is a redirect a shopper is
    # waiting on: an unforeseen shape in the upstream payload must cost them
    # the merchant page, not show them a 500.
    try:
        link, store_name = resolve_merchant_link(product_id)
    except Exception as e:
        sentry_sdk.capture_exception(e)
        link, store_name = None, ""

    # One retry with a freshly minted token. A resolve can come back empty
    # because the token expired sooner than MERCHANT_TOKEN_MAX_AGE assumed, and
    # the difference between "retry once" and "give up" is the difference
    # between the merchant's own page and a Google Shopping detour. Guarded by
    # `reminted` so a click can never cost more than one extra call, and only
    # attempted when the URL carries the query needed to rebuild the feed.
    if not link and not reminted and is_valid_query(recover_q):
        if _remint_tokens(recover_q, recover_s):
            reminted = True
            entry = merchant_routes.get(product_id) or entry
            fallback = trustscan.safe_link(entry.get("fallback", ""))
            fallback = fallback if fallback != "#" else "/"
            try:
                link, store_name = resolve_merchant_link(product_id)
            except Exception as e:
                sentry_sdk.capture_exception(e)
                link, store_name = None, ""

    if not link:
        return redirect(fallback, code=302)

    link = trustscan.safe_link(link)
    if link == "#":
        return redirect(fallback, code=302)

    # The card was filtered on the Google domain, which tells us nothing about
    # the seller. Now that the real domain is known, apply the same threshold
    # the feed applies — a listing that would have been hidden must not become
    # reachable just because the trust check happened too early.
    if trustscan.ENABLED:
        try:
            verdict = trustscan.score_url(
                link, store=store_name or entry.get("store", ""), deep=DEEP_TRUST)
            if verdict and not trustscan.is_trusted(verdict):
                return render_untrusted_merchant_page(
                    link, store_name or entry.get("store", ""), verdict)
        except Exception as e:
            sentry_sdk.capture_exception(e)

    return redirect(link, code=302)


def render_untrusted_merchant_page(link, store, verdict):
    """Warn before handing a shopper to a merchant that failed TrustScan.

    Deliberately an interstitial rather than a hard block: the shopper asked
    for this specific listing, and the score is a heuristic. They get the
    reason and an explicit way through.
    """
    from markupsafe import escape

    domain = escape((verdict or {}).get("domain", "") or "")
    score = (verdict or {}).get("score")
    score_txt = "%s/100" % score if isinstance(score, (int, float)) else "unrated"
    reason = escape(((verdict or {}).get("flags")
                     or [(verdict or {}).get("verdict", "Below the trust threshold")])[0])
    store_txt = escape(store or domain or "this store")
    href = escape(link)

    html = f"""<!DOCTYPE html>
<html lang="en">
<head>
  <meta charset="UTF-8"/>
  <meta name="viewport" content="width=device-width,initial-scale=1"/>
  <title>Check this store — ProductFilter</title>
  <style>
    *{{margin:0;padding:0;box-sizing:border-box}}
    body{{background:#0b0f0c;color:#e8e6df;min-height:100vh;display:flex;
      align-items:center;justify-content:center;padding:24px;
      font-family:system-ui,-apple-system,"Segoe UI",sans-serif;line-height:1.55}}
    .card{{text-align:center;max-width:460px}}
    .icon{{font-size:3.5rem;margin-bottom:20px}}
    h1{{font-size:1.75rem;font-weight:800;letter-spacing:-.02em;margin-bottom:10px}}
    p{{color:#9aa39b;margin-bottom:18px}}
    .box{{background:#141a15;border:1px solid #26302a;border-radius:16px;
      padding:18px 22px;margin-bottom:22px;text-align:left}}
    .box b{{display:block;color:#e2604a;font-size:1.1rem;margin-bottom:6px}}
    .box span{{font-size:.85rem;color:#9aa39b}}
    .row{{display:flex;gap:12px;justify-content:center;flex-wrap:wrap}}
    a.btn{{display:inline-block;padding:12px 20px;border-radius:12px;
      text-decoration:none;font-weight:700;font-size:.95rem}}
    a.back{{background:#1d4a2a;color:#e8f5e9}}
    a.on{{background:transparent;color:#9aa39b;border:1px solid #26302a}}
    .foot{{color:#5d655e;font-size:.75rem;margin-top:20px}}
  </style>
</head>
<body>
  <div class="card">
    <div class="icon">⚠️</div>
    <h1>Check this store first</h1>
    <p>TrustScan rated <b>{store_txt}</b> below the threshold ProductFilter uses to show sellers.</p>
    <div class="box">
      <b>{domain or store_txt} — {score_txt}</b>
      <span>{reason}</span>
    </div>
    <div class="row">
      <a class="btn back" href="/">Take me back</a>
      <a class="btn on" href="{href}" rel="noopener noreferrer nofollow">Continue anyway</a>
    </div>
    <p class="foot">Scores are automated and can be wrong. Nothing is bought or shared on your behalf.</p>
  </div>
</body>
</html>"""
    return html, 200


def _normalise_title(text):
    """Loose key for matching a stored alert title against a cached listing."""
    return re.sub(r"[^a-z0-9]+", " ", (text or "").lower()).strip()


def _find_in_cached_feeds(title):
    """Locate one product across every feed already in cache. Costs nothing.

    Price alerts are created from a card the shopper was looking at, so the
    product is by definition a row in one of the category feeds this worker has
    already paid for. Searching those feeds answers the alert for free and with
    data no staler than the feed itself.
    """
    want = _normalise_title(title)
    if not want:
        return None

    best = None
    best_ts = -1.0
    with _state_lock:
        entries = list(cache.items())

    for _key, entry in entries:
        products, ts = (entry[0] or []), entry[1]
        for product in products:
            have = _normalise_title(product.get("title"))
            if not have:
                continue
            # Exact match, or either title contained in the other: feeds
            # sometimes append a variant suffix ("... (8GB/128GB)") that the
            # stored alert title does not carry.
            if have == want or want in have or have in want:
                if ts > best_ts:
                    best, best_ts = product, ts
    return best


@app.route("/api/price-check")
def price_check():
    title = request.args.get("title", "").strip()
    # Same bounds as every other entry point. An unbounded title was a free
    # cache-miss generator, and each miss is a billable SerpApi call.
    if not is_valid_query(title):
        return {"error": "Invalid query"}, 400

    # CREDIT-WASTE FIX. This endpoint is unauthenticated and takes an arbitrary
    # title, and it used to hand that title straight to a billable search. A
    # product title is a long, specific string, so it never matched a cache key
    # and every single check was a guaranteed paid call — one per saved alert,
    # per device, every 30 minutes (see static/sw.js), forever. Ten users with
    # five alerts each was 800 credits a day for a background feature nobody
    # was watching, and anyone who found the URL could spend the quota at the
    # rate limit (50/min) just by varying the title.
    #
    # Alerts are now answered from the feeds already in cache, which is where
    # the alert came from in the first place.
    if _is_automated_client():
        return {"current_price": None, "link": None, "source": "blocked"}, 403

    cached = _find_in_cached_feeds(title)
    if cached is not None:
        value = extract_price(cached)
        price = None if value == float("inf") else value
        link = trustscan.safe_link(cached.get("link", ""))
        return {
            "current_price": price,
            "link": link if link != "#" else None,
            "store": cached.get("store", ""),
            "source": "cache",
        }

    # Nothing in cache. Going upstream from here is a paid call triggered by a
    # background timer rather than by a person, so it is opt-in and capped by
    # the same unattended budget as pre-warm.
    if not PRICE_CHECK_ALLOW_UPSTREAM:
        return {"current_price": None, "link": None, "source": "miss"}
    if not auto_credit_available():
        return {"current_price": None, "link": None, "source": "budget"}

    with crediting("price_check"):
        products = get_product_prices(title)
    if not products:
        return {"current_price": None, "link": None, "source": "upstream"}

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
        "store": best.get("store", ""),
        "source": "upstream",
    }


# ===============================
# CREDIT USAGE (credit-waste fix 2026-09-15)
# ===============================
@app.route("/api/credit-usage")
def credit_usage():
    """Today's SerpApi spend, attributed to whoever caused it.

    This is the endpoint that answers "is my quota going to users or to my own
    code?" without a code audit. Compare `user_driven` against `automatic`:

        curl -H "Authorization: Bearer $CREDIT_STATS_TOKEN" \\
             https://your-host/api/credit-usage

    Counts are per worker process and reset at UTC midnight, so with more than
    one worker, poll it a few times — `pid` tells you which one answered.

    Requires CREDIT_STATS_TOKEN. Unset, the route 404s: spend figures are
    operational data and should not be public.
    """
    if not CREDIT_STATS_TOKEN:
        return {"error": "not found"}, 404

    supplied = (request.headers.get("Authorization", "")
                .replace("Bearer ", "", 1).strip()
                or request.args.get("token", "").strip())
    # Constant-time compare: a token checked with == leaks its prefix to anyone
    # willing to measure the response.
    if not hmac.compare_digest(supplied, CREDIT_STATS_TOKEN):
        return {"error": "unauthorized"}, 401

    snapshot = credit_snapshot()
    snapshot["prewarm"] = {
        "enabled": PREWARM,
        "running_here": _prewarm_started,
        "interval_seconds": PREWARM_INTERVAL,
        "active_hours_utc": PREWARM_ACTIVE_HOURS,
        "in_active_window_now": _in_active_hours(),
        "demand_window_seconds": PREWARM_DEMAND_WINDOW,
        "categories_in_demand": sorted(
            slug for slug in category_rules.CATEGORIES
            if _category_in_demand(slug, _read_prewarm_state())
        ),
    }
    return snapshot


# ===============================
# ROBOTS
# ===============================
@app.route("/robots.txt")
def robots():
    """Crawl rules.

    This file was referenced in three code comments as the thing that keeps
    crawlers off the paid routes, but it was never actually served — the route
    did not exist, so every bot got a 404 and crawled whatever it liked. The
    /go bot check caught the honest ones by User-Agent; this closes the gap for
    the ones that read robots.txt but do not announce themselves.

    /go/ is disallowed because each click resolves a merchant link upstream at
    one credit a time, and /api/ because price-check and trust are machine
    endpoints with no crawl value. Category and product pages stay open — they
    are the content worth indexing, and they are served from cache.
    """
    body = (
        "User-agent: *\n"
        "Disallow: /go/\n"
        "Disallow: /api/\n"
        "Allow: /\n"
    )
    return body, 200, {
        "Content-Type": "text/plain; charset=utf-8",
        "Cache-Control": "public, max-age=86400",
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

# Assets worth having before they are needed. Deliberately assets only — the
# previous list also precached five category pages, so a service-worker install
# paid for five HTML documents (each a potential cold SerpApi miss) before the
# visitor had asked for any of them. Navigations are handled by the fetch
# handler's network-first path instead.
SW_PRECACHE = [
    "js/productfilter.js",
    "notifications.js",
    "fonts/bricolage-grotesque.woff2",
    "fonts/spline-sans-mono.woff2",
    "icons/icon-72.webp",
    "icons/icon-128.webp",
]


@app.route("/sw.js")
def sw():
    """Serve the service worker with its precache list resolved at runtime.

    sw.js stays a plain JavaScript file on disk (lintable, editable); the
    placeholders in it are substituted here so that:

      * precached URLs are the same content-hashed URLs the pages request, so
        the worker warms the cache the browser will actually consult rather than
        storing a second, unversioned copy of every asset, and
      * CACHE_NAME changes whenever any precached asset changes, which is what
        makes the activate handler's old-cache sweep do something useful. The
        fixed 'productfilter-v1' meant a deploy could leave a stale bundle
        pinned in a returning visitor's browser indefinitely.
    """
    with open(os.path.join(app.static_folder, "sw.js"), encoding="utf-8") as fh:
        body = fh.read()

    urls = [static_url(name) for name in SW_PRECACHE]
    urls.append(url_for("index"))          # the offline navigation fallback

    fingerprint = hashlib.md5("|".join(urls).encode("utf-8")).hexdigest()[:10]

    body = body.replace("'__CACHE_NAME__'",
                        json.dumps("productfilter-" + fingerprint))
    body = body.replace("__STATIC_ASSETS__", json.dumps(urls))
    body = body.replace("'__NOTIFY_ICON__'",
                        json.dumps(static_url("icons/icon-192.png")))
    body = body.replace("'__NOTIFY_BADGE__'",
                        json.dumps(static_url("icons/icon-72.png")))

    resp = app.response_class(body, mimetype="text/javascript")
    # A worker served from /sw.js already controls the whole origin, but being
    # explicit survives someone moving the file later.
    resp.headers["Service-Worker-Allowed"] = "/"
    return resp

@app.route("/manifest.json")
def manifest():
    return app.send_static_file("manifest.json")

# ===============================
# SECURITY HEADERS
# ===============================
def _cache_policy(resp):
    """Attach a deliberate Cache-Control to every response (fix 02).

    Before this, static assets went out as `no-cache` with a 1980-01-01
    last-modified and HTML carried no cache-control at all, so every repeat
    visit re-fetched every byte.
    """
    path = request.path

    # Never cache an error, a redirect, or the result of a search POST.
    #
    # HEAD counts as safe here, not as "not a GET". Werkzeug routes HEAD to the
    # GET view but leaves request.method as "HEAD", so an earlier version of
    # this check answered every HEAD with no-store — which is what a CDN, a
    # link checker or `curl -I` sees, and it contradicted the policy the same
    # URL returns on GET.
    if request.method not in ("GET", "HEAD") or resp.status_code >= 400:
        resp.headers["Cache-Control"] = "no-store"
        return resp

    if path.startswith("/static/"):
        if request.args.get("v"):
            # Content-hashed URL: the bytes behind it can never change.
            resp.headers["Cache-Control"] = (
                "public, max-age=%d, immutable" % STATIC_MAX_AGE)
        else:
            resp.headers["Cache-Control"] = (
                "public, max-age=%d" % STATIC_UNVERSIONED_MAX_AGE)

        # The upstream 1980-01-01 last-modified is a build artefact, not a
        # fact about the file. Left in place it invites revalidation against a
        # date that means nothing; the ETag Flask sends is the real validator.
        last_modified = resp.headers.get("Last-Modified", "")
        if "198" in last_modified[:20] and "1980" in last_modified:
            del resp.headers["Last-Modified"]
        return resp

    # The service worker and the manifest control what everything else caches,
    # so they must always be revalidated — a stale sw.js pins a stale app.
    if path in ("/sw.js", "/manifest.json"):
        resp.headers["Cache-Control"] = "public, max-age=0, must-revalidate"
        return resp

    if path.startswith("/api/") or path.startswith("/go/"):
        resp.headers["Cache-Control"] = "no-store"
        return resp

    # HTML: no browser caching (prices must look live), but a shared cache may
    # hold it briefly and serve it stale while revalidating — which is the same
    # bargain fix 01 makes on the server side.
    if resp.mimetype == "text/html":
        resp.headers["Cache-Control"] = (
            "public, max-age=0, s-maxage=%d, stale-while-revalidate=%d"
            % (HTML_SMAX_AGE, HTML_STALE_WHILE_REVALIDATE))
    else:
        # Anything else (JSON probes such as /health) is state, not content.
        resp.headers["Cache-Control"] = "no-store"
    return resp


@app.after_request
def add_headers(resp):
    _cache_policy(resp)

    resp.headers["X-Frame-Options"] = "DENY"
    resp.headers["X-Content-Type-Options"] = "nosniff"
    resp.headers["Referrer-Policy"] = "strict-origin-when-cross-origin"
    resp.headers["Permissions-Policy"] = "geolocation=(), microphone=(), camera=(), interest-cohort=()"
    resp.headers["Cross-Origin-Opener-Policy"] = "same-origin"

    # Only meaningful over TLS, and only safe to send when the site is
    # actually HTTPS-only. Enabled by default in production.
    if os.getenv("ENABLE_HSTS", "1") in ("1", "true", "True"):
     resp.headers["Strict-Transport-Security"] = "max-age=31536000; includeSubDomains"

    if request.path.startswith("/go/"):
     resp.headers["X-Robots-Tag"] = "noindex, nofollow, noarchive"

# script-src is strict: no 'unsafe-inline', no external script hosts.

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
        # Fonts are self-hosted as of speed-test fix 03, so neither Google
        # font host is needed here any more — one less third-party origin
        # this page is allowed to talk to.
        "style-src 'self' 'unsafe-inline'; "
        "font-src 'self'; "
        "script-src 'self'; "
        "connect-src 'self'; "
        "form-action 'self'; "
        "frame-ancestors 'none'; "
        "base-uri 'self'; "
        "object-src 'none'"
    )
    return resp

