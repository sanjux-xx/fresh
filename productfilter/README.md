# ProductFilter — Smart Price Comparison 🛒

ProductFilter is an open-source price comparison web app built with **Python (Flask)** and powered by the **[SerpApi Google Shopping API](https://serpapi.com/)*. It helps users find the best prices for phones, laptops, groceries, and more — pulling live results from trusted Indian retailers like Amazon, Flipkart, Croma, and Tata CLiQ.

🌐 **Live Site: [productfilter.dev](https://productfilter.dev)**

---

## ✨ Features

- 🔍 **Live product search** via SerpApi's Google Shopping engine
- 📱 **Smart mobile phone filtering** — strips accessories, resale listings, and irrelevant junk
- 🏷️ **Variant grouping** — groups iPhone Pro, Pro Max, Mini, and Base models separately
- 💸 **Best-price ranking** — prioritizes trusted stores and sorts by price
- 🛡️ **Rate limiting & IP blocking** to prevent abuse
- ⚡ **In-memory caching** (20-minute TTL) to reduce API calls
- 🐞 **Sentry integration** for error monitoring
- 🍎 **Food/grocery category** powered by a dedicated blueprint (`food_backend.py`)
- 🔒 **Security headers** (X-Frame-Options, X-Content-Type-Options)

---

## 🏗️ Tech Stack

| Layer | Technology |
|---|---|
| Backend | Python 3, Flask |
| Search API | [SerpApi](https://serpapi.com/) (Google Shopping) |
| Error Tracking | Sentry SDK |
| Deployment | Heroku (Procfile included) |
| Frontend | HTML/Jinja2 templates |

---

## 🚀 Getting Started

### Prerequisites

- Python 3.8+
- A [SerpApi](https://serpapi.com/) API key
- (Optional) A Sentry DSN for error monitoring

### Installation

```bash
# 1. Clone the repo
git clone https://github.com/sanjux-xx/ProductFilter.git
cd ProductFilter

# 2. Install dependencies
pip install -r requirements.txt

# 3. Set environment variables
export SERPAPI_KEY="your_serpapi_key_here"
export SENTRY_DSN="your_sentry_dsn_here"   # optional

# 4. Run the app
python app.py
```

Then open [http://localhost:5000](http://localhost:5000) in your browser.

---

## 🌐 Deployment (Heroku)

```bash
heroku create
heroku config:set SERPAPI_KEY=your_key_here
heroku config:set SENTRY_DSN=your_dsn_here
git push heroku main
```

The `Procfile` is already configured for Heroku deployment.

---

## 📁 Project Structure

```
ProductFilter/
├── app.py              # Main Flask app — routes, filtering, SerpApi logic
├── food_backend.py     # Blueprint for food/grocery category
├── requirements.txt    # Python dependencies
├── Procfile            # Heroku process config
├── templates/          # Jinja2 HTML templates
│   └── index.html
│   └── category.html
└── static/
    └── images/         # Static assets
```

---

## 🔑 Environment Variables

| Variable | Required | Description |
|---|---|---|
| `SERPAPI_KEY` |  Yes | Your SerpApi API key |
| `SENTRY_DSN` |  Optional | Sentry project DSN for error tracking |

---

## 🛍️ Supported Categories

| URL | Category |
|---|---|
| `/` | General product search |
| `/category/mobiles` | Mobile phones |
| `/category/laptops` | Laptops |
| `/category/fruits` | Fresh fruits |
| `/category/groceries` | Grocery items |

---

## Powered By

Search results are powered by **[SerpApi](https://serpapi.com/)** — a real-time SERP API that provides structured Google Shopping data. This project uses SerpApi under their [Open-Source Sponsorship Program](https://serpapi.com/open-source-sponsorship).


---

## 🤝 Contributing

Pull requests are welcome! For major changes, please open an issue first to discuss what you'd like to change.

1. Fork the repo
2. Create your feature branch: `git checkout -b feature/your-feature`
3. Commit your changes: `git commit -m 'Add your feature'`
4. Push to the branch: `git push origin feature/your-feature`
5. Open a Pull Request

---

## 📄 License

This project is open source. See [LICENSE](LICENSE) for details.

---

## 🔗 Links

- 🌐 [productfilter.dev](https://productfilter.dev) — Live website
- 🔎 [SerpApi](https://serpapi.com/) — Search API powering this project
- 📦 [Flask](https://flask.palletsprojects.com/) — Web framework
- 🐞 [Sentry](https://sentry.io/) — Error monitoring
---

# 🛡️ TrustScan AI — site trust filtering

ProductFilter now scores **every merchant link before it reaches your screen**.
Anything scoring at or below **50/100** is removed from the results and
reported as a "N low-trust listings hidden" notice you can expand to see why.

## How it works

```
SerpApi results
      │
      ▼
trustscan.py ── heuristics (offline, instant)
      │         · brand impersonation: typosquats, leetspeak, look-alikes
      │         · URL structure: raw IPs, punycode, @-tricks, deep subdomains
      │         · phishing vocabulary: login / verify / suspended in the host
      │         · TLD abuse rates: .tk .ml .xyz .top …
      │
      ├─────── OpenPhish live blocklist    (no key, cached 10 min)
      ├─────── Google Safe Browsing        (optional free key, batched)
      └─────── RDAP domain age + DNS       (deep mode only, cached 24h)
      │
      ▼
ai_helper.py ── tie-break vote on borderline stores (score 40-60)
      │         plain-English verdict for each store
      │
      ▼
score > 50 ? ──yes──▶ shown, with a trust badge
      │
      └──no──▶ hidden, counted in the notice
```

Scores run 0-97, higher is safer. A **critical** signal (brand impersonation,
raw IP, link shortener, brand + bait keywords) caps the score at 38. A
**confirmed blocklist hit** caps it at 15. Verified major retailers
(Amazon, Flipkart, Croma, Reliance, Tata CLiQ, 1mg, …) get a score floor of 82
so a messy affiliate URL can never bury a real store.

### Shopping-specific tuning

Four signals are treated more harshly here than in the generic TrustScan
engine, because in a price-comparison context they have no legitimate use:

| Signal | Generic engine | ProductFilter |
|---|---|---|
| Raw IP address | −15 points | critical (capped at 38) |
| Link shortener | −10 points | critical — a merchant must be nameable |
| Brand + bait keywords | −18 points | critical — the classic phishing shape |
| Known Indian retailer | no special case | score floor of 82 |

## Performance

Scores are cached **per domain for 24h**, not per URL — every Amazon product
link is different but the trust answer is identical. After warm-up a typical
search does zero extra network calls. The OpenPhish feed is fetched once per
10 minutes for the whole process, and Safe Browsing is a single batched call.

## Configuration

Everything is optional and off-by-default-safe. See `.env.example`.

```bash
TRUSTSCAN_MIN_SCORE=50    # must score ABOVE this to be shown
TRUSTSCAN_DEEP=0          # 1 = also check domain age via RDAP
TRUSTSCAN_ENABLED=1       # 0 = disable filtering entirely
```

## Debugging

Two endpoints make the filter inspectable:

```bash
# why was this store hidden?
curl "localhost:8000/api/trust?url=some-shop.xyz&deep=1"

# is the layer alive, and how much AI quota is left today?
curl "localhost:8000/api/trust-status"
```

---

# 🤖 The AI layer (optional, free)

Three small features, all of which **degrade silently to heuristics** when no
key is set, the quota runs out, or the provider is down:

1. **Plain-English verdicts** — "New domain imitating a known brand — avoid."
2. **Borderline tie-breaks** — for stores scoring 40-60, where pure heuristics
   are weakest, the AI casts a deciding vote (±12/−20 points).
3. **Query cleanup** — fixes "ifone 16 pro maxx" before it hits SerpApi.

## Providers

| Provider | Free tier | Role |
|---|---|---|
| **Google Gemini 2.5 Flash-Lite** | ~1,500 req/day, 30 req/min, no card | primary |
| **Groq (Llama 3.3 70B)** | ~1,000 req/day, no card | automatic fallback |

Get the keys at [aistudio.google.com/apikey](https://aistudio.google.com/apikey)
and [console.groq.com/keys](https://console.groq.com/keys), then:

```bash
export GEMINI_API_KEY="..."
export GROQ_API_KEY="..."     # optional but recommended
```

A provider that returns 429 is put on a 5-minute cooldown and traffic shifts
to the other one automatically.

## Why 200+ searches/day is not a problem

AI answers are **cached on disk per domain**, and verdicts are **batched**
(one call judges up to 12 stores). There are only a few hundred merchant
domains in Indian shopping results, so after a day or two of warm-up most
searches make **zero** AI calls. `AI_DAILY_BUDGET` (default 800) is a hard
stop regardless.

---

# ✅ Testing

An offline smoke test runs the whole app against a mocked SerpApi payload —
no API key, no network required:

```bash
TRUSTSCAN_FEEDS=0 AI_ENABLED=0 python3 test_trustscan.py
```

It asserts that Amazon/Flipkart/Croma survive, that a typosquat, a leetspeak
domain, a phishing TLD, a raw IP and a shortener are all filtered out, and
that the receipt layout, trust badges, price-alert modal and PWA manifest all
still render.

---

# 🎨 Frontend

`templates/index.html` and `templates/category.html` are the receipt-themed
redesign: paper/ink palette, rupee-green best-price highlight, marigold
accent, mono tabular prices, and a per-category accent colour driven by the
slug. The previous versions are kept in `templates/legacy/` for reference.

Preserved from the old frontend: the price-alerts panel and modal
(`static/notifications.js` IDs and function names are unchanged), the service
worker registration, and the PWA manifest/icons. Tailwind is no longer loaded
— the handful of utility classes that `notifications.js` injects at runtime
are provided by a small CSS shim at the bottom of `index.html`.

The food pages (`food.html`, `food_brand.html`, `food_item.html`,
`food_compare.html`) still use their original dark theme. Their merchant links
are trust-filtered server-side, but they have not been restyled yet.

---

# 🔐 Security

Two offline test suites ship with the app. Neither touches a live host — both
drive the Flask test client against a mocked SerpApi.

```bash
python3 pentest.py     # 60 attack checks: XSS, SSRF, injection, DoS, evasion
python3 bugtest.py     # 77 robustness checks: malformed data, concurrency, edge cases
python3 bugtest2.py    # 71 logic checks: price parsing, grouping, categories, JS contract
python3 test_trustscan.py   # end-to-end filtering behaviour
```

## Hardening applied

| Area | Issue found | Fix |
|---|---|---|
| XSS | `javascript:` / `data:` / `file:` links from SerpApi reached `href`, because an unparseable URL scored `None` and `None` was treated as "unknown, allow" | Unparseable URLs are now always rejected, plus a `\|safe_url` Jinja filter collapses any non-http(s) URL to `#` |
| Trust bypass | `https://user:pass@evil.tk@amazon.in/` ended at a real hostname and inherited the retailer score floor | Embedded credentials are now critical, and the floor is skipped for any critical / userinfo / non-HTTPS URL |
| Trust bypass | `https://ama%7Azon.in/` — percent-encoding in the host defeated every string check | Percent signs in a hostname are now critical |
| Trust bypass | A hostile *link* was rescued by its *store name* (slugify "Evil" → `evil.com` → clean score) | Store-name fallback only applies when there is no link at all, and only for explicitly known retailers |
| Transport | Plain HTTP scored 85 on a known retailer | HTTP is critical for merchant links (`TRUSTSCAN_ALLOW_HTTP=1` to soften) |
| Rate limiting | `CF-Connecting-IP` was trusted unconditionally, so anyone could reset their own bucket per request | Header honoured only when `TRUST_PROXY_HEADERS=1`; defaults to `remote_addr` |
| DoS | Price cache and per-IP tables grew without limit | `MAX_CACHE_ENTRIES` (500) and `MAX_TRACKED_IPS` (10,000), with pruning of expired entries |
| Prompt injection | Store names and domains from SerpApi went into AI prompts verbatim, so a newline plus "ignore previous instructions" could flip a trust vote | Domains and free text are sanitized and length-capped before prompting; replies are matched back on the sanitized form |
| AI trust | A vote could in principle lift a blocklisted store | `_apply_vote` refuses to touch blocklisted or invalid entries |
| SSRF | RDAP lookups interpolated the domain into a URL path unencoded | Percent-encoded via `_rdap_url()` |
| Headers | No CSP, Referrer-Policy, HSTS or Permissions-Policy | All added in `add_headers` |

## Bugs fixed

**In the new layers**

- Non-string values in a SerpApi `link` field (int, None, nested object) crashed the scorer.
- An offer with a missing link got an empty trust dict, which read as "unknown" and let it through.
- An unexpected exception inside the AI layer could surface in a search request.
- The "You save" figure almost never appeared: it compared *products*, but identical listings from different stores collapse into one product. It now compares the offers within the cheapest product.
- When every listing was filtered out, the empty state didn't use the "N low-trust listings hidden" wording, so the explanation was easy to miss.

**In the original ProductFilter logic**

- **Price parsing dropped real listings.** `extract_price` only understood
  `"₹69,999"`. Every other shape SerpApi returns — `Rs. 69,999`, `INR 69999`,
  `from ₹69,999`, `₹69,999 onwards`, `₹69,999*`, `$799.00` — parsed as
  infinity and was silently discarded downstream. Now a tolerant numeric
  extraction that keeps Indian lakh grouping intact.
- **Identical products from different stores did not merge.** The grouping key
  was the first five words of the title, so `iPhone 16 128GB Black` and
  `iPhone 16 128GB (Black)` became two separate products — which broke the
  entire point of the app: no multi-store offers list, no "N stores compared",
  no savings figure. The key now drops colour/marketing noise and keeps spec
  tokens (128gb, 8gb, 6.7inch) so real variants still separate.
- **The medicine filter could show phones.** It ended in
  `return filtered if filtered else products`, so when nothing matched it
  returned *everything*. A pharmacy search could list smartphones and clothing.
  It now returns nothing rather than the wrong thing.
- **The phone accessory filter ran on every query.** It requires a phone
  keyword in each title, so on "atta 10kg" it removed all results and the same
  fallback quietly restored the unfiltered list — the filter appeared to work
  while doing nothing. It now only runs when the query actually looks like a
  phone search.
- A `javascript:` value in a SerpApi `thumbnail` field rendered into `img src`.

## Known limitations

- **`style-src` still needs `'unsafe-inline'`** for the inline `<style>` blocks
  and per-row style attributes. `script-src` is strict (`'self'` only) — all
  behaviour moved to `static/js/productfilter.js` and inline `onclick` handlers were
  replaced with delegated `data-action` bindings, so injected markup cannot
  execute. Style injection is a much weaker primitive.
- **SerpApi redirect links can't be attributed.** When SerpApi returns a
  `google.com/shopping` URL for an unknown merchant, the score describes
  Google, not the shop behind it.
- **Rate limiting is per-process and in-memory.** With multiple gunicorn
  workers each has its own counters, so the effective limit is
  `RATE_LIMIT × workers`. A shared store (Redis) would be needed for a hard limit.
- **No CSRF protection on the search forms.** They are unauthenticated and
  perform no state change, so the impact is nil today — but any future
  logged-in feature will need tokens.
