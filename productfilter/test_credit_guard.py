"""Guards on unattended SerpApi spend (credit-waste fix, 2026-09-15).

Run offline:  python3 test_credit_guard.py

Every check below counts *billable upstream calls*, not HTTP responses. The bug
this file exists to prevent was not a crash — the app worked perfectly while
spending the quota on itself around the clock — so the only assertion that
matters is "how many times did we reach for the paid API, and who asked".

The real SerpApi client is replaced with a counter before app import, so this
file never touches the network and never costs a credit.
"""

import os
import sys
import time
import types

HERE = os.path.dirname(os.path.abspath(__file__))
sys.path.insert(0, HERE)

# ---------------------------------------------------------------------------
# Environment must be set before app import: the module reads every one of
# these at import time.
# ---------------------------------------------------------------------------
os.environ["SERPAPI_KEY"] = "test-key-not-real"
os.environ["PREWARM"] = "0"            # started manually, per test
os.environ["AI_ENABLED"] = "0"
os.environ["SENTRY_DSN"] = ""
os.environ["CREDIT_STATS_TOKEN"] = "test-token"
os.environ["PREWARM_STATE_PATH"] = "/tmp/pf-test-prewarm-state.json"
os.environ["PREWARM_LOCK_PATH"] = "/tmp/pf-test-prewarm.lock"
for stale in (os.environ["PREWARM_STATE_PATH"], os.environ["PREWARM_LOCK_PATH"]):
    try:
        os.remove(stale)
    except OSError:
        pass

# ---------------------------------------------------------------------------
# Fake SerpApi client. Counts calls; returns one plausible shopping row.
# ---------------------------------------------------------------------------
UPSTREAM_CALLS = []


class FakeSearch(object):
    def __init__(self, params=None):
        self.params = params or {}
        self.timeout = None

    def get_dict(self):
        UPSTREAM_CALLS.append(self.params.get("q", ""))
        return {
            "shopping_results": [{
                "title": "Test Phone 5G 128GB",
                "price": "₹19,999",
                "source": "Amazon.in",
                "link": "https://www.amazon.in/dp/TEST",
                "thumbnail": "https://example.com/t.jpg",
                "product_id": "123456",
                "immersive_product_page_token": "tok123",
            }]
        }


fake_serpapi = types.ModuleType("serpapi")
fake_serpapi.GoogleSearch = FakeSearch
sys.modules["serpapi"] = fake_serpapi

import app                                           # noqa: E402
import category_rules                                # noqa: E402

app.GoogleSearch = FakeSearch

FAILURES = []
CHECKS = [0]


def check(label, passed, detail=""):
    CHECKS[0] += 1
    print("  %-4s %-58s %s" % ("ok" if passed else "FAIL", label, detail))
    if not passed:
        FAILURES.append(label)


def reset():
    """Clear everything a previous check could have warmed or counted."""
    del UPSTREAM_CALLS[:]
    app.cache.clear()
    app.merchant_routes.clear()
    with app._credit_lock:
        app._credit_counts.clear()
        app._credit_day = app._utc_day()
    try:
        os.remove(app.PREWARM_STATE_PATH)
    except OSError:
        pass


# ===========================================================================
print("\n1. PRE-WARM IS DEMAND-GATED")
print("=" * 76)

reset()
app.PREWARM_DEMAND_WINDOW = 6 * 60 * 60
app.PREWARM_ACTIVE_HOURS = "0-24"

spent = app._prewarm_once()
check("no visitors -> pre-warm spends nothing",
      spent == 0 and not UPSTREAM_CALLS,
      "%d upstream calls" % len(UPSTREAM_CALLS))

reset()
app.note_category_demand("mobiles")
spent = app._prewarm_once()
check("one category browsed -> only that category is warmed",
      spent == 1 and len(UPSTREAM_CALLS) == 1,
      "%d of %d categories" % (len(UPSTREAM_CALLS),
                               len(category_rules.CATEGORIES)))

reset()
for slug in category_rules.CATEGORIES:
    app.note_category_demand(slug)
spent = app._prewarm_once()
check("all categories browsed -> all are warmed",
      spent == len(category_rules.CATEGORIES),
      "%d calls" % len(UPSTREAM_CALLS))

# Demand goes stale.
reset()
app.note_category_demand("mobiles")
state = app._read_prewarm_state()
state["mobiles"] = time.time() - (7 * 60 * 60)        # older than the window
import json                                          # noqa: E402
with open(app.PREWARM_STATE_PATH, "w") as fh:
    json.dump(state, fh)
spent = app._prewarm_once()
check("demand older than the window stops being paid for",
      spent == 0, "%d upstream calls" % len(UPSTREAM_CALLS))

# A crawler must not count as demand.
reset()
client = app.app.test_client()
client.get("/category/mobiles", headers={"User-Agent": "Googlebot/2.1"})
state = app._read_prewarm_state()
check("a crawler visit does not register as demand",
      "mobiles" not in state, "state=%s" % sorted(state))

# ===========================================================================
print("\n2. PRE-WARM RESPECTS QUIET HOURS")
print("=" * 76)

reset()
for slug in category_rules.CATEGORIES:
    app.note_category_demand(slug)

app.PREWARM_ACTIVE_HOURS = "3-19"
hour = time.gmtime().tm_hour
inside = 3 <= hour < 19
check("_in_active_hours agrees with the wall clock",
      app._in_active_hours() == inside,
      "hour=%02d UTC, window 03-19, active=%s" % (hour, inside))

# Force the window closed regardless of when the suite runs.
app.PREWARM_ACTIVE_HOURS = "%d-%d" % ((hour + 2) % 24, (hour + 3) % 24)
spent = app._prewarm_once()
check("outside the active window -> pre-warm spends nothing",
      spent == 0 and not UPSTREAM_CALLS,
      "%d upstream calls" % len(UPSTREAM_CALLS))

app.PREWARM_ACTIVE_HOURS = "0-24"
check("0-24 is always active", app._in_active_hours())
check("a wrapping window is parsed", app._parse_active_hours("19-3") == (19, 3))
check("an unparseable window falls back to always-on",
      app._parse_active_hours("garbage") == (0, 24))

# ===========================================================================
print("\n3. UNATTENDED DAILY BUDGET")
print("=" * 76)

reset()
app.AUTO_CREDIT_DAILY_BUDGET = 2
for slug in category_rules.CATEGORIES:
    app.note_category_demand(slug)

spent = app._prewarm_once()
check("pre-warm stops at the daily budget",
      len(UPSTREAM_CALLS) <= 2,
      "%d calls against a budget of 2" % len(UPSTREAM_CALLS))

check("budget is reported as exhausted", not app.auto_credit_available())

# A shopper is never blocked by the automatic budget.
before = len(UPSTREAM_CALLS)
app.get_product_prices("oneplus 13", scope="mobiles")
check("a user-facing search still runs when the auto budget is spent",
      len(UPSTREAM_CALLS) == before + 1,
      "%d -> %d" % (before, len(UPSTREAM_CALLS)))

snapshot = app.credit_snapshot()
check("spend is attributed to the right sources",
      snapshot["by_source"].get("prewarm", 0) > 0
      and snapshot["by_source"].get("user_search", 0) == 1,
      str(snapshot["by_source"]))
check("automatic and user-driven are reported separately",
      snapshot["automatic"] + snapshot["user_driven"] == snapshot["total"],
      "auto=%d user=%d total=%d" % (snapshot["automatic"],
                                    snapshot["user_driven"],
                                    snapshot["total"]))

app.AUTO_CREDIT_DAILY_BUDGET = 0
check("a budget of 0 means unlimited", app.auto_credit_available())
app.AUTO_CREDIT_DAILY_BUDGET = 150

# ===========================================================================
print("\n4. PRICE ALERTS COST NOTHING")
print("=" * 76)

reset()
# Warm one category, the way a shopper browsing it would.
app.get_product_prices(category_rules.CATEGORIES["mobiles"].build_query(""),
                       scope="mobiles")
warmed = len(UPSTREAM_CALLS)

resp = client.get("/api/price-check?title=Test Phone 5G 128GB")
body = resp.get_json()
check("an alert on a cached product is answered from cache",
      resp.status_code == 200 and body.get("source") == "cache"
      and body.get("current_price") == 19999.0,
      str(body))
check("answering it cost no upstream call",
      len(UPSTREAM_CALLS) == warmed,
      "%d -> %d" % (warmed, len(UPSTREAM_CALLS)))

before = len(UPSTREAM_CALLS)
resp = client.get("/api/price-check?title=Some Product Nobody Cached 9000")
body = resp.get_json()
check("an uncached alert does not reach upstream by default",
      body.get("source") == "miss" and len(UPSTREAM_CALLS) == before,
      str(body))

before = len(UPSTREAM_CALLS)
resp = client.get("/api/price-check?title=Test Phone 5G 128GB",
                  headers={"User-Agent": "python-requests/2.32"})
check("a bot cannot spend credits on price-check",
      resp.status_code == 403 and len(UPSTREAM_CALLS) == before,
      "HTTP %d" % resp.status_code)

app.PRICE_CHECK_ALLOW_UPSTREAM = True
before = len(UPSTREAM_CALLS)
resp = client.get("/api/price-check?title=Another Uncached Thing 1234")
check("upstream is reachable when explicitly enabled",
      len(UPSTREAM_CALLS) == before + 1,
      "%d -> %d" % (before, len(UPSTREAM_CALLS)))
check("and that spend is labelled price_check",
      app.credit_snapshot()["by_source"].get("price_check", 0) == 1,
      str(app.credit_snapshot()["by_source"]))
app.PRICE_CHECK_ALLOW_UPSTREAM = False

# ===========================================================================
print("\n5. SINGLE-WORKER PRE-WARM LOCK")
print("=" * 76)

app._prewarm_lock_handle = None
first = app._claim_prewarm_slot()
check("the first process claims the pre-warm slot", first)

# Simulate a second worker: same lock file, a separate handle.
import subprocess                                    # noqa: E402
probe = subprocess.run(
    [sys.executable, "-c",
     "import fcntl,sys\n"
     "h=open(%r,'w')\n"
     "try:\n"
     "    fcntl.flock(h.fileno(), fcntl.LOCK_EX|fcntl.LOCK_NB)\n"
     "    print('GOT')\n"
     "except OSError:\n"
     "    print('BLOCKED')\n" % app.PREWARM_LOCK_PATH],
    capture_output=True, text=True)
check("a second worker is refused the slot",
      "BLOCKED" in probe.stdout, probe.stdout.strip() or probe.stderr.strip())

# ===========================================================================
print("\n6. CRAWL RULES AND SPEND REPORTING")
print("=" * 76)

resp = client.get("/robots.txt")
text = resp.get_data(as_text=True)
check("robots.txt is actually served", resp.status_code == 200,
      "HTTP %d" % resp.status_code)
check("robots.txt keeps crawlers off the billable redirect",
      "Disallow: /go/" in text, text.replace("\n", " | ").strip())

resp = client.get("/api/credit-usage")
check("credit usage needs a token", resp.status_code == 401,
      "HTTP %d" % resp.status_code)

resp = client.get("/api/credit-usage?token=test-token")
check("credit usage reports the split with a token",
      resp.status_code == 200 and "automatic" in resp.get_json(),
      "HTTP %d" % resp.status_code)

resp = client.get("/api/credit-usage?token=wrong")
check("a wrong token is rejected", resp.status_code == 401,
      "HTTP %d" % resp.status_code)

# ===========================================================================
print("\n" + "=" * 76)
if FAILURES:
    print("SUMMARY: %d checks, %d FAILED" % (CHECKS[0], len(FAILURES)))
    for name in FAILURES:
        print("  - " + name)
    print("=" * 76)
    sys.exit(1)

print("SUMMARY: %d checks, all passed" % CHECKS[0])
print("=" * 76)
sys.exit(0)
test_credits