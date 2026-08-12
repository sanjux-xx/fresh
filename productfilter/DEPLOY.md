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

Unchanged from before — the GitHub Actions workflow still targets the Azure Web
App named `productcomparison`. That is the resource name, not the domain; leave
it alone unless you are moving the app itself.

    Procfile:  web: gunicorn app:app --bind 0.0.0.0:8000

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

---

## 6. Known limitations

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
