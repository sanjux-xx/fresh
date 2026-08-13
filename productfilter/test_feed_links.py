"""Offline checks for the SerpApi feed -> usable listing path.

These exist because of a live outage in which every category page except
Mobiles rendered empty, and every multi-word search returned nothing anywhere
on the site. Nothing was wrong with the filters or the API key: SerpApi had
stopped returning `direct_link`/`merchant_link` and now returns only
`product_link`, which is a google.com/search URL with the search query
interpolated into it UNENCODED.

Run: python3 test_feed_links.py
"""

import sys
import types

# Stub SerpApi if it isn't installed
if "serpapi" not in sys.modules:
    try:
        import serpapi  # noqa: F401
    except ImportError:
        stub = types.ModuleType("serpapi")

        class GoogleSearch:
            def __init__(self, params):
                self.params = params

            def get_dict(self):
                return {}

        stub.GoogleSearch = GoogleSearch
        sys.modules["serpapi"] = stub

import app
import category_rules as cr
import trustscan

failures = []


def check(label, got, want):
    if got == want:
        print(f"ok: {label}")
    else:
        print(f"FAIL: {label}\\n  got={got!r}\\n  want={want!r}")
        failures.append(label)


def usable(link):
    return trustscan.safe_link(app.normalize_feed_link(link)) != "#"


GOOGLE = "https://www.google.com/search?ibp=oshop"


def main():
    print("Feed links with unencoded spaces")

    check(
        "multi-word query link is usable",
        usable(GOOGLE + "&q=laptop price India&prds=productid:12345"),
        True,
    )

    check(
        "two-word search link is usable",
        usable(GOOGLE + "&q=iphone 16&prds=productid:12345"),
        True,
    )

    check(
        "single-word query link is usable",
        usable(GOOGLE + "&q=smartphone&prds=productid:12345"),
        True,
    )

    check(
        "space becomes %20",
        app.normalize_feed_link(GOOGLE + "&q=hp laptop"),
        GOOGLE + "&q=hp%20laptop",
    )

    check(
        "already encoded link stays encoded",
        app.normalize_feed_link(GOOGLE + "&q=hp%20laptop"),
        GOOGLE + "&q=hp%20laptop",
    )

    print("\\nBlock terms match correctly")

    groceries = cr.get("groceries")

    ok, why = cr.explain(
        {
            "title": "VEDIC VITA Roasted Peanuts 500 GM",
            "store": "Amazon.in",
        },
        groceries,
        "",
    )
    check("groceries keeps roasted peanuts", (ok, why), (True, "ok"))

    ok, why = cr.explain(
        {
            "title": "Silicone Back Cover Case for iPhone 16",
            "store": "Amazon.in",
        },
        cr.get("mobiles"),
        "",
    )
    check(
        "mobiles blocks phone case",
        (ok, why),
        (False, "blocked term: back cover"),
    )

    print("\\nQuery building")

    check(
        "fruits query template",
        cr.get("fruits").build_query("mango"),
        "fresh mango fruit buy online India",
    )

    check(
        "laptops query dedupes laptop",
        cr.get("laptops").build_query("hp laptop"),
        "hp laptop price India",
    )

    if failures:
        print(f"\\nFAILURES ({len(failures)}):")
        for f in failures:
            print(" -", f)
        return 1

    print("\\nAll checks passed")
    return 0


if __name__ == "__main__":
    sys.exit(main())