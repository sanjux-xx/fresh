"""
Pre-deployment checks for ProductFilter.

Catches the things that only bite in production: a committed secret, a missing
dependency, debug mode left on, a template pointing at a static file that
isn't there. Run before every deploy:

    python3 deploycheck.py
"""

import os
import re
import sys
import ast
import json
import types

os.environ.setdefault("TRUSTSCAN_FEEDS", "0")
os.environ.setdefault("AI_ENABLED", "0")
os.environ.pop("SENTRY_DSN", None)

HERE = os.path.dirname(os.path.abspath(__file__))
RESULTS = []


def check(name, passed, detail=""):
    RESULTS.append((name, passed, detail))
    print("  %-4s %-58s %s" % ("PASS" if passed else "FAIL", name, detail))


def read(p):
    with open(os.path.join(HERE, p), encoding="utf-8") as fh:
        return fh.read()


PY_FILES = [f for f in os.listdir(HERE) if f.endswith(".py")]
APP_FILES = ["app.py", "trustscan.py", "ai_helper.py", "food_backend.py"]

# ===========================================================================
print("\n" + "=" * 76)
print("1. SECRETS")
print("=" * 76)

# Real key shapes, not the words themselves — the code legitimately mentions
# GEMINI_API_KEY etc. by name.
SECRET_PATTERNS = [
    (r"AIza[0-9A-Za-z_\-]{30,}", "Google API key"),
    (r"gsk_[0-9A-Za-z]{40,}", "Groq key"),
    (r"sk-[0-9A-Za-z]{32,}", "OpenAI-style key"),
    (r"https://[0-9a-f]{32}@[a-z0-9.\-]+/\d+", "Sentry DSN with secret"),
    (r"\b[0-9a-f]{64}\b", "64-char hex secret (SerpApi shape)"),
]

scanned = 0
leaks = []
for root, dirs, files in os.walk(HERE):
    dirs[:] = [d for d in dirs if d not in (".git", "__pycache__", "node_modules", "legacy")]
    for f in files:
        if not f.endswith((".py", ".html", ".js", ".json", ".md", ".txt", ".yml", ".example")):
            continue
        p = os.path.join(root, f)
        try:
            body = open(p, encoding="utf-8", errors="ignore").read()
        except Exception:
            continue
        scanned += 1
        for pat, label in SECRET_PATTERNS:
            for m in re.finditer(pat, body):
                leaks.append("%s in %s: %s…" % (label, os.path.relpath(p, HERE), m.group(0)[:12]))

check("no hard-coded credentials in %d files" % scanned, not leaks,
      leaks[0] if leaks else "")

check(".env is gitignored", ".env" in read(".gitignore"))
check(".ai_cache.json is gitignored", ".ai_cache.json" in read(".gitignore"))
check("no .env file is present in the tree",
      not os.path.exists(os.path.join(HERE, ".env")))
check(".env.example ships no filled-in values",
      not re.search(r"^(SERPAPI_KEY|GEMINI_API_KEY|GROQ_API_KEY|SENTRY_DSN)=.+$",
                    read(".env.example"), re.M))

# every key read from the environment is documented
used = set()
for f in APP_FILES:
    used |= set(re.findall(r'os\.getenv\("([A-Z_0-9]+)"', read(f)))
documented = set(re.findall(r"^([A-Z_0-9]+)=", read(".env.example"), re.M))
check("every env var is documented in .env.example", used <= documented,
      "undocumented: %s" % sorted(used - documented) if used - documented
      else "%d vars" % len(used))
check("no stale vars documented", documented <= used,
      "stale: %s" % sorted(documented - used) if documented - used else "")

# ===========================================================================
print("\n" + "=" * 76)
print("2. DEPENDENCIES")
print("=" * 76)

reqs_raw = read("requirements.txt")
reqs = {re.split(r"[=<>\[]", l.strip())[0].lower()
        for l in reqs_raw.splitlines() if l.strip() and not l.startswith("#")}

# sys.stdlib_module_names only exists on 3.10+; fall back to an explicit list
# so this check still works on the 3.9 runtimes some hosts still default to.
STDLIB = set(getattr(sys, "stdlib_module_names", ())) or {
    "os", "re", "sys", "json", "time", "math", "ast", "socket", "logging",
    "threading", "collections", "datetime", "urllib", "types", "functools",
    "itertools", "pathlib", "random", "string", "typing", "hashlib", "base64",
    "subprocess", "shutil", "tempfile", "traceback", "warnings", "copy",
    "unicodedata", "html", "http", "email", "csv", "io", "enum", "abc",
    # The 3.9 fallback list was incomplete, so a stdlib import could be
    # reported as a missing dependency on exactly the runtimes this branch
    # exists to support.
    "ipaddress", "ssl", "secrets", "uuid", "textwrap", "difflib", "struct",
    "decimal", "statistics", "operator", "contextlib", "dataclasses", "gzip",
}
LOCAL = {os.path.splitext(f)[0] for f in PY_FILES}
DIST = {"flask": "flask", "requests": "requests", "serpapi": "google-search-results",
        "sentry_sdk": "sentry-sdk", "gunicorn": "gunicorn"}

imported = set()
for f in APP_FILES:
    tree = ast.parse(read(f))
    for node in ast.walk(tree):
        if isinstance(node, ast.Import):
            imported |= {a.name.split(".")[0] for a in node.names}
        elif isinstance(node, ast.ImportFrom) and node.module and node.level == 0:
            imported.add(node.module.split(".")[0])

third_party = {m for m in imported if m not in STDLIB and m not in LOCAL}
missing = []
for mod in sorted(third_party):
    dist = DIST.get(mod, mod).lower()
    if dist not in reqs and mod.lower() not in reqs:
        missing.append(mod)
check("every third-party import is in requirements.txt", not missing,
      "missing: %s" % missing if missing else ", ".join(sorted(third_party)))

check("gunicorn is pinned for production", "gunicorn" in reqs)
check("Procfile exists", os.path.exists(os.path.join(HERE, "Procfile")))
proc = read("Procfile") if os.path.exists(os.path.join(HERE, "Procfile")) else ""
check("Procfile launches the app with gunicorn",
      "gunicorn" in proc and "app:app" in proc, proc.strip())

# ===========================================================================
print("\n" + "=" * 76)
print("3. RUNTIME CONFIG")
print("=" * 76)

app_src = read("app.py")
check("debug mode is not enabled anywhere",
      not re.search(r"debug\s*=\s*True", app_src))
check("app.run() is not called at import time",
      not re.search(r"^\s*app\.run\(", app_src, re.M))
check("SECRET_KEY is not hard-coded",
      not re.search(r"SECRET_KEY\s*=\s*['\"]", app_src))

# import the app and inspect the live object
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
    f2 = types.ModuleType("sentry_sdk.integrations.flask")
    f2.FlaskIntegration = lambda *a, **k: None
    sys.modules["sentry_sdk"] = s
    sys.modules["sentry_sdk.integrations"] = i
    sys.modules["sentry_sdk.integrations.flask"] = f2

sys.path.insert(0, HERE)
import trustscan
import app as productfilter

check("app.debug is False", productfilter.app.debug is False)
check("app.testing is False by default", productfilter.app.testing is False)
check("TRUST_PROXY_HEADERS defaults to off (safe without a proxy)",
      productfilter.TRUST_PROXY_HEADERS is False)
check("TrustScan is enabled by default", trustscan.ENABLED is True)
check("threshold is 50 by default", trustscan.MIN_SCORE == 50)

# ===========================================================================
print("\n" + "=" * 76)
print("4. STATIC ASSETS AND TEMPLATES")
print("=" * 76)

TEMPLATES = [f for f in os.listdir(os.path.join(HERE, "templates")) if f.endswith(".html")]
missing_assets = []
for t in TEMPLATES:
    body = read(os.path.join("templates", t))
    for ref in re.findall(r'(?:src|href)="(/static/[^"?#]+)"', body):
        if not os.path.exists(os.path.join(HERE, ref.lstrip("/"))):
            missing_assets.append("%s -> %s" % (t, ref))
check("every /static reference resolves to a real file", not missing_assets,
      missing_assets[0] if missing_assets else "%d templates" % len(TEMPLATES))

for f in ("static/notifications.js", "static/js/productfilter.js", "static/sw.js",
          "static/manifest.json", "static/icons/icon-192.png"):
    check("%s present" % f, os.path.exists(os.path.join(HERE, f)))

# every template compiles
# Use the APP's Jinja environment, not a bare one — the templates rely on the
# custom |safe_url filter that app.py registers, so a standalone environment
# would report a false failure.
bad = []
for t in TEMPLATES:
    try:
        productfilter.app.jinja_env.get_template(t)
    except Exception as e:
        bad.append("%s: %s" % (t, e))
check("all templates parse (with the app's filters)", not bad,
      bad[0] if bad else "%d templates" % len(TEMPLATES))

# Short pages (the food picker, a category before any search) used to leave a
# band of blank paper under the footer because nothing forced the page to fill
# the viewport. Every rendered template must keep the sticky-footer layout.
PAGE_TEMPLATES = ["index.html", "category.html", "food.html",
                  "food_brand.html", "food_item.html"]
no_sticky = []
for t_ in PAGE_TEMPLATES:
    body = read(os.path.join("templates", t_))
    if "min-height:100vh" not in body or "main{flex:1 0 auto}" not in body:
        no_sticky.append(t_)
check("every page template has the sticky-footer layout", not no_sticky,
      "missing in: %s" % no_sticky if no_sticky else "%d templates" % len(PAGE_TEMPLATES))

# Responsive coverage. The food item page once hid its Order button on phones,
# which removed the only link out to Swiggy/Zomato — a control that is the
# whole point of the page must never be display:none on mobile.
for t_ in PAGE_TEMPLATES:
    body = read(os.path.join("templates", t_))
    check("%s has a phone breakpoint" % t_,
          "max-width:560px" in body or "max-width:430px" in body)

item = read(os.path.join("templates", "food_item.html"))
mobile_block = item[item.find("@media(max-width:560px)"):] if "@media(max-width:560px)" in item else ""
check("food item Order button survives on mobile",
      ".prow .order{display:none}" not in mobile_block)

for t_ in ("index.html", "category.html"):
    body = read(os.path.join("templates", t_))
    check("%s wraps long text on narrow phones" % t_, "overflow-wrap:anywhere" in body)

# ---------------------------------------------------------------------------
# Branding: nothing user-facing may still say CostShot or point at the old
# domain. A half-finished rename is the kind of thing that ships unnoticed.
BRAND, DOMAIN, OLD_BRAND = "ProductFilter", "productfilter.dev", "ostShot"
brand_files = ["templates/" + t_ for t_ in PAGE_TEMPLATES] + [
    "static/manifest.json", "static/sw.js", "static/notifications.js",
    "static/js/productfilter.js", "README.md"]
stale = [f for f in brand_files if OLD_BRAND in read(f)]
check("no user-facing file still says the old brand", not stale,
      "found in: %s" % stale if stale else "%d files clean" % len(brand_files))

old_domain = [f for f in brand_files if "productcamparison" in read(f)]
check("no reference to the old domain", not old_domain,
      "found in: %s" % old_domain if old_domain else "")

mani = json.loads(read("static/manifest.json"))
check("manifest carries the new brand", mani["short_name"] == BRAND, mani["short_name"])
check("manifest theme colour matches the live design",
      mani["theme_color"] == "#0E7A4D", mani["theme_color"])
check("service worker cache name was bumped for the rebrand",
      "productfilter-v" in read("static/sw.js"))
check("README points at the new domain", DOMAIN in read("README.md"))

for t_ in PAGE_TEMPLATES:
    body = read(os.path.join("templates", t_))
    check("%s has description + Open Graph tags" % t_,
          'name="description"' in body and 'og:site_name' in body)

TAGLINE = "Every price. Only real sellers."
for t_ in PAGE_TEMPLATES:
    body = read(os.path.join("templates", t_))
    check("%s carries the tagline in the wordmark" % t_,
          TAGLINE in body and 'class="tagline"' in body)

# the description is the search-result snippet: too long and Google truncates it
desc = re.search(r'<meta name="description" content="([^"]+)"', read("templates/index.html"))
check("meta description is a sensible length",
      desc is not None and 80 <= len(desc.group(1)) <= 165,
      "%d chars" % len(desc.group(1)) if desc else "missing")
check("manifest description matches the meta description",
      json.loads(read("static/manifest.json"))["description"] == (desc.group(1) if desc else None))

# ---------------------------------------------------------------------------
# Price alerts. The feature shipped on the search page only — category pages
# had no button, no modal and did not even load the alerts script, so a whole
# surface silently lacked the feature. Both listing pages must carry all of it.
for t_ in ("index.html", "category.html"):
    body = read(os.path.join("templates", t_))
    check("%s includes the alerts control" % t_, '_alerts.html' in body)
    check("%s includes the alert modal + scripts" % t_, '_alert_modal.html' in body)
    check("%s has a labelled per-product alert button" % t_,
          'class="alertbtn"' in body and 'data-action="open-alert"' in body)
    check("%s alert button passes title, price and link" % t_,
          all(a in body for a in ("data-title=", "data-price=", "data-link=")))

modal = read(os.path.join("templates", "_alert_modal.html"))
for el in ("alert-modal", "modal-inner", "modal-product-title",
           "modal-current-price", "modal-target-price"):
    check("modal partial keeps #%s" % el, 'id="%s"' % el in modal)
panel = read(os.path.join("templates", "_alerts.html"))
for el in ("bell-btn", "bell-badge", "alerts-panel", "alerts-list"):
    check("alerts partial keeps #%s" % el, 'id="%s"' % el in panel)
# The banner must ship hidden: revealing it is the browser's decision, via
# beforeinstallprompt. A banner that renders unconditionally would nag users
# who already installed the app.
inst = read(os.path.join("templates", "_install.html"))
card = read(os.path.join("templates", "_install_card.html"))
check("header install button ships hidden", 'id="install-btn" class="hidden"' in inst)
check("install card ships hidden", 'id="install-card" class="hidden"' in card)
check("install card has both actions",
      'data-action="install-app"' in card and 'data-action="dismiss-install"' in card)
check("install card carries iOS instructions", "ic-ios" in card)
check("install is not a fixed bottom bar",
      all("#install-banner" not in read(os.path.join("templates", t_))
          for t_ in PAGE_TEMPLATES))

# "{#" opens a Jinja comment. In CSS, "@media(...){#some-id" silently turns the
# rest of the file into an unterminated comment and the template stops
# compiling — it cost a broken build once already.
for t_ in PAGE_TEMPLATES + ["_install.html", "_install_card.html", "_alerts.html",
                            "_alert_modal.html"]:
    body = read(os.path.join("templates", t_))
    check("%s has no accidental Jinja comment opener in CSS" % t_,
          not re.search(r"\{#(?=[A-Za-z-])", body))

pfjs = read(os.path.join("static", "js", "productfilter.js"))
check("captures beforeinstallprompt", "beforeinstallprompt" in pfjs)
check("hides the prompt once installed", "appinstalled" in pfjs)
# The old version stored a permanent dismissal, so the banner never came back
# after an uninstall. The flag must expire and be cleared on install.
check("dismissal expires rather than being permanent", "DISMISS_DAYS" in pfjs)
check("installing clears the dismissal so uninstall re-offers it",
      "removeItem(DISMISS_KEY)" in pfjs)
check("never prompts while running as an installed app",
      "display-mode: standalone" in pfjs)
check("iOS Safari gets the manual instruction path", "isIosSafari" in pfjs)

# ---------------------------------------------------------------------------
# Client-side injection. Saved alerts replay listing data — including titles a
# marketplace seller wrote — so nothing user-derived may become HTML, and no
# runtime-injected control may rely on an inline handler that the CSP blocks.
notif = read(os.path.join("static", "notifications.js"))
notif_code = re.sub(r"/\*.*?\*/", "", notif, flags=re.S)
notif_code = re.sub(r"^\s*//.*$", "", notif_code, flags=re.M)

tainted = [f for f in re.findall(r"innerHTML\s*=\s*[`'\"](.*?)[`'\"]\s*;", notif_code, re.S)
           if "${" in f]
check("no user data is interpolated into innerHTML", not tainted,
      "%d tainted template(s)" % len(tainted))
check("no inline event handlers in runtime-injected markup",
      not re.search(r"on(?:click|change|submit)\s*=", notif_code))
check("saved alert links are validated before use", "safeLink" in notif_code)
check("alert list is built with DOM APIs", "createElement" in notif_code)

check("modal partial loads both scripts",
      "/static/notifications.js" in modal and "/static/js/productfilter.js" in modal)

# a button nested inside an anchor is invalid HTML and swallows its own clicks
cat = read(os.path.join("templates", "category.html"))
check("category rows do not nest the alert button inside a link",
      'class="rowmain"' in cat and '<a class="rrow' not in cat)

# ---------------------------------------------------------------------------
# Alignment. Two patterns caused visible misalignment and are easy to
# reintroduce: baseline alignment on a row holding a tall icon and short text,
# and fixed-size dots/tiles that a flex parent is free to squeeze.
for t_ in PAGE_TEMPLATES:
    body = read(os.path.join("templates", t_))
    check("%s uses no baseline alignment on flex rows" % t_,
          "align-items:baseline" not in body)

    dots = _RE_DOT.findall(body) if False else re.findall(r"\.[\w -]*\.?dot\{([^}]*)\}", body)
    check("%s dots cannot be squeezed by their flex parent" % t_,
          all("flex-shrink:0" in d for d in dots), "%d dot rules" % len(dots))

    # Group by selector before judging: a media-query override that only
    # changes the size still inherits flex-shrink from the base rule, so
    # checking each rule in isolation produces false failures.
    tiles = {}
    for sel, decl in re.findall(r"(\.[\w .-]*(?:icon|ic|brand-mark|shield))\{([^}]*)\}", body):
        key = sel.strip().split()[-1]
        tiles.setdefault(key, []).append(decl)
    unprotected = [k for k, decls in tiles.items()
                   if any("width:" in d and "height:" in d for d in decls)
                   and not any("flex-shrink:0" in d for d in decls)]
    check("%s icon tiles cannot be squeezed" % t_, not unprotected,
          "unprotected: %s" % unprotected if unprotected else "%d tiles" % len(tiles))

    # The install prompt was lost once already, in the redesign. Every page
    # must carry the banner and the script that reveals it.
    check("%s includes the install control" % t_, '_install.html' in body)
    check("%s loads the app script that drives it" % t_,
          "/static/js/productfilter.js" in body or '_alert_modal.html' in body)

    if ".search{" in body:
        rule = re.search(r"\.search\{([^}]*)\}", body).group(1)
        check("%s search bar centres its controls" % t_, "align-items:center" in rule)

# ===========================================================================
print("\n" + "=" * 76)
print("5. ROUTES")
print("=" * 76)

productfilter.GoogleSearch = _MS
productfilter.app.config["TESTING"] = True
cl = productfilter.app.test_client()

EXPECTED = ["/", "/category/<category_name>", "/api/price-check", "/api/trust",
            "/api/trust-status", "/health", "/sw.js", "/manifest.json",
            "/food/", "/food/<brand>", "/food/<brand>/<item_slug>"]
rules = {str(r) for r in productfilter.app.url_map.iter_rules()}
for e in EXPECTED:
    check("route %s registered" % e, e in rules)

for path in ("/", "/health", "/manifest.json", "/sw.js", "/api/trust-status",
             "/category/mobiles", "/category/laptops", "/category/groceries",
             "/category/fruits", "/category/medicine", "/food/"):
    productfilter.cache.clear()
    productfilter.request_log.clear()
    productfilter.blocked_ips.clear()
    r = cl.get(path, follow_redirects=True)
    check("GET %s -> 200" % path, r.status_code == 200, "HTTP %s" % r.status_code)

# ===========================================================================
print("\n" + "=" * 76)
fails = [r for r in RESULTS if not r[1]]
print("SUMMARY: %d checks, %d passed, %d FAILED" %
      (len(RESULTS), len(RESULTS) - len(fails), len(fails)))
print("=" * 76)
if fails:
    for name, _, detail in fails:
        print("  %s %s" % (name, ("— " + detail) if detail else ""))
    sys.exit(1)
print("Ready to deploy.")
