# Deploying ProductFilter to productfilter.dev

Everything below assumes you are replacing the existing deployment. There is no
database, no migration step and no build step — it is a Flask app plus static
files.

---

## 1. Environment variables

Set these in your hosting provider's config panel. Full annotated list is in
`.env.example`; these are the ones that matter.

**Required**

    SERPAPI_KEY=            your existing key

**Free AI keys — get both, they fail over to each other**

    GEMINI_API_KEY=         aistudio.google.com/apikey    (~1,500 req/day)
    GROQ_API_KEY=           console.groq.com/keys         (~1,000 req/day)

**Set these two for your setup**

    TRUST_PROXY_HEADERS=1   you are behind Cloudflare
    ENABLE_HSTS=1           .dev is HSTS-preloaded, so this must be on

**Optional**

    GOOGLE_SAFE_BROWSING_KEY=   widens scam detection
    SENTRY_DSN=                 your existing DSN works unchanged

**Performance (added for the 2026-08-13 speed-test fixes — all have defaults)**

    PREWARM=1               keep category feeds warm in the background
    PREWARM_INTERVAL=900    seconds between pre-warm cycles
    STALE_TTL=86400         how long an expired feed may still be served
    SERPAPI_TIMEOUT=30      hang-guard on one upstream call, seconds — must stay
                            above SerpApi's real cold latency (3.6-11.5 s) and
                            below gunicorn's 45 s worker timeout
    MAX_REFRESH_THREADS=2   concurrent background refreshes per worker
    STATIC_MAX_AGE=31536000 lifetime of a content-hashed /static URL
    HTML_SMAX_AGE=120       how long a shared cache may hold an HTML page

Cost note: pre-warming costs one SerpApi call per category per worker per
cycle. With the defaults (5 categories, 2 workers, 15 minutes) that is about
40 calls an hour, and it is what keeps the cold path off your visitors. Raise
`PREWARM_INTERVAL` to spend less, or set `PREWARM=0` to opt out entirely.

Everything else has a working default. Do not set `TRUSTSCAN_PUBLIC_DEEP=1`
unless you want anonymous callers to trigger outbound RDAP lookups.

If your host has a read-only filesystem, also set:

    AI_CACHE_PATH=/tmp/.ai_cache.json

---

## 2. Before you deploy

    python3 deploycheck.py

145 checks: no committed secrets, dependencies match imports, debug off, every
static reference resolves, every template parses, all routes registered. If it
fails, do not deploy — it is checking the things that only break in production.

To run the whole suite:

    python3 test_trustscan.py    # end-to-end filtering
    python3 pentest.py           # 60  attack checks
    python3 pentest2.py          # 46  second-pass attacks
    python3 pentest3.py          # 25  client-side attacks
    python3 bugtest.py           # 77  robustness
    python3 bugtest2.py          # 93  logic
    python3 bugtest3.py          # 44  recent surfaces

None of them need an API key or network access.

---

## 3. Deploy

The app runs on **Northflank**, which builds from this repository — pushing to
`main` is the deploy. There is no separate deploy workflow in this repo.

    Procfile:  web: gunicorn app:app --bind 0.0.0.0:8000 -c gunicorn.conf.py

### Binary assets are generated, not hand-authored

`static/fonts/*.woff2` and `static/icons/*` are build outputs. Regenerate and
commit them whenever `build_fonts.py`, `generate_icons.py` or
`static/images/logo.png` changes:

    pip install fonttools brotli pillow
    python3 build_fonts.py        # -> static/fonts/*.woff2      (~56 KB total)
    python3 generate_icons.py     # -> static/icons/*.{webp,png}
    git add static/fonts static/icons && git commit -m "assets: rebuild" && git push

Both scripts are deterministic, so re-running them is always safe.
`deploycheck.py` fails if the font files are absent, which is the intended
guard — the templates preload them and the page falls back to system fonts
without them.

If you would rather CI did this, `docs/build-assets.yml.example` is a ready
GitHub Actions workflow that runs both scripts and commits the result; move it
to `.github/workflows/build-assets.yml` to enable it.

---

## 4. Point the domain

Order matters on a `.dev` domain: **TLS must be live before DNS**, because
browsers refuse plain HTTP to `.dev` outright — a misconfigured site will look
completely dead rather than merely insecure.

1. Add `productfilter.dev` to the host, provision the certificate
2. Confirm `https://productfilter.dev/health` returns `{"status":"ok"}`
3. Then switch DNS

In Sentry, add `productfilter.dev` under Settings → Client Keys → allowed
domains, or errors from the new host are dropped silently.

---

## 5. Check these by hand

Automated tests never ran a browser. These four take ten minutes and cover
what they structurally could not reach:

- [ ] Search for something real. Do prices, stores and trust badges look right?
- [ ] Save a price alert, then reopen the alerts panel. Does it list correctly,
      and does the ✕ remove it?
- [ ] Install to the home screen, uninstall, revisit. Does the install offer
      come back?
- [ ] Open a category page on your phone. Is anything cramped or overflowing?
- [ ] DevTools → Application → Service Workers: does it say **activated**? The
      install used to fail on a missing icon path, so this is worth confirming
      once rather than assuming.
- [ ] Load a page twice. On the second load, every `/static/...` request should
      come from disk cache, not the network.

---

## 6. Verify the performance fixes on production

The speed test that prompted these changes measured from a single vantage point
through an egress proxy, so its figures are worth confirming against your own
edge.

**HTTP/2 (report fix 05) — a Northflank port setting, not a code change.**
The report hedged that the HTTP/1.1 it saw might have been its own proxy. It
almost certainly was not: Northflank's own documentation states that existing
HTTP ports stay on HTTP/1 and must be switched by the user, and that the
`istio-envoy` server header the report recorded is their edge. Confirm, then
fix in the dashboard:

    curl -sI --http2 https://productfilter.dev/ -o /dev/null -w '%{http_version}\n'

If that prints `1.1`: open the service in Northflank → **Ports & DNS** → edit
the public port → set protocol to **HTTP/2** → save. No restart is required,
and Northflank downgrades automatically for clients that cannot speak h2, so
there is nothing to roll back if it misbehaves. This compounds with the font
and caching work above, because the remaining requests can then multiplex over
one connection.

    https://northflank.com/docs/v1/application/network/configure-ports

**Cold-path TTFB (report fix 01, fixed in code).** Re-measure the route the
report found worst, first request after a deploy and again a minute later:

    curl -s -o /dev/null -w 'cold %{time_starttransfer}s\n' https://productfilter.dev/category/fruits
    curl -s -o /dev/null -w 'warm %{time_starttransfer}s\n' https://productfilter.dev/category/fruits

The report's baseline was 11.54 s cold / 50 ms warm. With pre-warming on, the
first number should now look like the second. If it does not, check that
`SERPAPI_KEY` is set in the deployed environment — pre-warming deliberately
no-ops without it, and logs `prewarm: skipped, no SERPAPI_KEY set` at startup.

**Cache headers.** One request confirms the whole of fix 02:

    curl -sI https://productfilter.dev/ | grep -i cache-control
    curl -sI "$(curl -s https://productfilter.dev/ | grep -o '/static/js/productfilter.js?v=[a-f0-9]*' | head -1 | sed 's|^|https://productfilter.dev|')" | grep -i cache-control

The HTML should report `s-maxage`, the hashed asset `max-age=31536000, immutable`.

---

## 7. Known limitations

- **Rate limiting is per-process.** With N gunicorn workers the effective limit
  is 50 × N per minute. A shared store would be needed for a hard limit.
- **`style-src` still allows `'unsafe-inline'`** because the templates carry
  inline `<style>` blocks. `script-src` is strict, which is the half that
  matters for XSS.
- **SerpApi redirect links cannot be attributed.** When SerpApi returns a
  `google.com/shopping` URL for an unknown merchant, the trust score describes
  Google, not the shop behind it.
- **No CSRF protection.** Nothing is authenticated and no request changes
  server state, so there is nothing to forge today. The first login feature
  will need tokens.
- **Price alerts are per-device.** They live in `localStorage` and only check
  while the site is open. Cross-device alerts, or alerts that fire overnight,
  need a database and a background worker.
