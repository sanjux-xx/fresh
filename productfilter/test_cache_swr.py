"""Offline checks for the stale-while-revalidate product cache.

No SerpApi key and no network: the upstream call is replaced with a stub, so
these tests assert the *cache policy* the 2026-08-13 speed test asked for —
that an expired entry is served immediately instead of making the shopper wait
on a cold 3.6-11.5 s upstream fetch.

Covered:
  1. fresh entry            -> served from cache, no upstream call
  2. expired entry          -> stale copy served immediately, refreshed async
  3. stale refresh          -> single-flighted, not once per concurrent reader
  4. upstream failure       -> stale copy reused rather than an empty page
  5. absent entry           -> one synchronous call, and it carries a timeout
  6. beyond STALE_TTL       -> refetched synchronously, no ancient data served

Run:  python3 test_cache_swr.py
"""

import os
import sys
import threading
import time

os.environ.setdefault("PREWARM", "0")

import app


# ---------------------------------------------------------------- stub upstream
class StubUpstream:
    """Stands in for _fetch_product_prices, recording how often it ran."""

    def __init__(self, products=None, fail=False, delay=0.0):
        self.products = products if products is not None else [{"title": "fresh"}]
        self.fail = fail
        self.delay = delay
        self.calls = 0
        self._lock = threading.Lock()

    def __call__(self, query, scope, cache_key):
        with self._lock:
            self.calls += 1
        if self.delay:
            time.sleep(self.delay)
        if self.fail:
            return None
        app.cache[cache_key] = (self.products, time.time(), [])
        return self.products


def setup(entry_age=None, products=None):
    """Reset cache state; optionally seed one entry aged entry_age seconds."""
    app.cache.clear()
    app._refresh_inflight.clear()
    key = app._cache_key_for("mango", "fruits")
    if entry_age is not None:
        cached = products if products is not None else [{"title": "cached"}]
        app.cache[key] = (cached, time.time() - entry_age, [])
    return key


def drain_refreshes(timeout=2.0):
    """Wait for background refresh threads to finish."""
    deadline = time.time() + timeout
    while time.time() < deadline:
        if not app._refresh_inflight:
            return True
        time.sleep(0.01)
    return False


FAILURES = []


def check(label, condition, detail=""):
    if condition:
        print("  ok   %s" % label)
    else:
        print("  FAIL %s %s" % (label, detail))
        FAILURES.append(label)


# ---------------------------------------------------------------------- tests
def test_fresh_is_served_without_upstream():
    print("1. fresh entry is served without an upstream call")
    setup(entry_age=10)                       # well inside CACHE_TTL
    stub = StubUpstream()
    app._fetch_product_prices = stub
    out = app.get_product_prices("mango", scope="fruits")
    check("no upstream call", stub.calls == 0, "(calls=%d)" % stub.calls)
    check("cached feed returned", out == [{"title": "cached"}], "(got %r)" % out)


def test_stale_is_served_immediately_and_refreshed():
    print("2. expired entry is served immediately, refreshed in background")
    key = setup(entry_age=app.CACHE_TTL + 60)   # stale, inside STALE_TTL
    stub = StubUpstream(delay=0.3)              # a slow upstream
    app._fetch_product_prices = stub

    started = time.time()
    out = app.get_product_prices("mango", scope="fruits")
    elapsed = time.time() - started

    check("returned the stale copy", out == [{"title": "cached"}], "(got %r)" % out)
    check("did not wait for upstream", elapsed < 0.2, "(took %.3fs)" % elapsed)
    check("refresh finished", drain_refreshes())
    check("refresh happened once", stub.calls == 1, "(calls=%d)" % stub.calls)
    check("cache now holds fresh data",
          app.cache[key][0] == [{"title": "fresh"}], "(got %r)" % (app.cache[key][0],))


def test_stale_refresh_is_single_flighted():
    print("3. concurrent readers of a stale key trigger one refresh")
    setup(entry_age=app.CACHE_TTL + 60)
    stub = StubUpstream(delay=0.25)
    app._fetch_product_prices = stub

    threads = [threading.Thread(target=app.get_product_prices,
                                args=("mango",), kwargs={"scope": "fruits"})
               for _ in range(10)]
    for t in threads:
        t.start()
    for t in threads:
        t.join()

    check("refresh finished", drain_refreshes())
    check("one paid call for ten readers", stub.calls == 1, "(calls=%d)" % stub.calls)


def test_upstream_failure_reuses_stale():
    print("4. upstream failure falls back to the stale copy")
    setup(entry_age=app.STALE_TTL + 3600, products=[{"title": "ancient"}])
    stub = StubUpstream(fail=True)
    app._fetch_product_prices = stub
    out = app.get_product_prices("mango", scope="fruits")
    check("upstream was attempted", stub.calls == 1, "(calls=%d)" % stub.calls)
    check("stale copy served, not []", out == [{"title": "ancient"}], "(got %r)" % out)


def test_absent_key_fetches_synchronously():
    print("5. absent entry fetches synchronously")
    setup(entry_age=None)
    stub = StubUpstream()
    app._fetch_product_prices = stub
    out = app.get_product_prices("mango", scope="fruits")
    check("one synchronous call", stub.calls == 1, "(calls=%d)" % stub.calls)
    check("fresh feed returned", out == [{"title": "fresh"}], "(got %r)" % out)


def test_beyond_stale_ttl_is_not_served():
    print("6. an entry past STALE_TTL is refetched, not served")
    setup(entry_age=app.STALE_TTL + 60, products=[{"title": "ancient"}])
    stub = StubUpstream()
    app._fetch_product_prices = stub
    out = app.get_product_prices("mango", scope="fruits")
    check("upstream called", stub.calls == 1, "(calls=%d)" % stub.calls)
    check("ancient data not served", out == [{"title": "fresh"}], "(got %r)" % out)


def test_timeout_is_bounded():
    print("7. the real upstream call is timeout-bounded")
    # Two-sided bound, and both sides have bitten in practice. The upper bound
    # guards against the client's own 60000 s default (no timeout at all) and
    # must stay under gunicorn's 45 s worker kill. The LOWER bound exists
    # because a 6 s value once cut off SerpApi's normal 3.6-11.5 s cold
    # responses mid-flight, making every uncached search render empty — the
    # timeout is a hang-guard and must clear real upstream latency.
    check("SERPAPI_TIMEOUT clears real upstream latency (>= 15s)",
          app.SERPAPI_TIMEOUT >= 15, "(got %r)" % app.SERPAPI_TIMEOUT)
    check("SERPAPI_TIMEOUT stays under gunicorn's 45s worker timeout",
          app.SERPAPI_TIMEOUT < 45, "(got %r)" % app.SERPAPI_TIMEOUT)
    src = open(os.path.join(os.path.dirname(os.path.abspath(__file__)),
                            "app.py")).read()
    check("timeout is applied to the client",
          "search.timeout = SERPAPI_TIMEOUT" in src)


def test_head_matches_get():
    """A HEAD must return the same cache policy as the GET it mirrors.

    Found in production: `curl -I` reported no-store on every URL while the
    same URLs returned immutable on GET. Werkzeug routes HEAD to the GET view
    but leaves request.method as "HEAD", so a `!= "GET"` check silently made
    every HEAD uncacheable — the version CDNs, monitors and link checkers see.
    """
    print("8. HEAD returns the same cache policy as GET")
    client = app.app.test_client()
    import re as _re
    home = client.get("/").get_data(as_text=True)
    match = _re.search(r"/static/js/productfilter\.js\?v=[0-9a-f]+", home)
    paths = ["/", "/sw.js", "/manifest.json"]
    if match:
        paths.append(match.group(0))

    for path in paths:
        get_cc = client.get(path).headers.get("Cache-Control")
        head_cc = client.head(path).headers.get("Cache-Control")
        check("HEAD %s matches GET" % path.split("?")[0], get_cc == head_cc,
              "(GET=%r HEAD=%r)" % (get_cc, head_cc))

    check("a POST is still never cached",
          client.post("/", data={"product_query": "x"})
                .headers.get("Cache-Control") == "no-store")


def main():
    real = app._fetch_product_prices
    try:
        test_fresh_is_served_without_upstream()
        test_stale_is_served_immediately_and_refreshed()
        test_stale_refresh_is_single_flighted()
        test_upstream_failure_reuses_stale()
        test_absent_key_fetches_synchronously()
        test_beyond_stale_ttl_is_not_served()
        test_timeout_is_bounded()
        test_head_matches_get()
    finally:
        app._fetch_product_prices = real
        app.cache.clear()

    print()
    if FAILURES:
        print("FAILED: %d check(s): %s" % (len(FAILURES), ", ".join(FAILURES)))
        return 1
    print("all cache checks passed")
    return 0


if __name__ == "__main__":
    sys.exit(main())
