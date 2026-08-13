"""Tests for merchant link resolution — /go/<product_id>.

The google_shopping engine returns no merchant URL, only a google.com link,
so clicking a listing used to land on Google Shopping. The merchant URL is
resolved lazily from the row's immersive_product_page_token when a shopper
clicks. These tests pin that behaviour.

Run: python3 test_merchant_links.py
"""

import os
import sys
import types

os.environ.setdefault("SERPAPI_KEY", "test-key")
os.environ.setdefault("TRUSTSCAN_ENABLED", "0")

SHOPPING = {"shopping_results": []}
IMMERSIVE = {"product_results": {}}

class _MockSearch:
    calls = []

    def __init__(self, params):
        self.params = params
        _MockSearch.calls.append(params)

    def get_dict(self):
        if self.params.get("engine") == "google_immersive_product":
            if "__replace__" in IMMERSIVE:
                return IMMERSIVE["__replace__"]
            return IMMERSIVE
        return SHOPPING

if "serpapi" not in sys.modules:
    stub = types.ModuleType("serpapi")
    stub.GoogleSearch = _MockSearch
    sys.modules["serpapi"] = stub
else:
    import serpapi
    serpapi.GoogleSearch = _MockSearch

import app

app.GoogleSearch = _MockSearch

failures = []

def check(label, got, want):
    if got == want:
        print(f"ok: {label}")
    else:
        print(f"FAIL: {label}\\n  got={got!r}\\n  want={want!r}")
        failures.append(label)

def reset_state():
    SHOPPING["shopping_results"] = []
    IMMERSIVE.clear()
    _MockSearch.calls.clear()
    app.cache.clear()
    app._merchant_cache.clear()

GOOGLE = "https://www.google.com/search?ibp=oshop"

def sample_row():
    return {
        "product_id": "1234567890123456789",
        "title": "Samsung Galaxy S25 256GB",
        "price": "₹74,999",
        "source": "Flipkart",
        "thumbnail": "https://img.test/s25.jpg",
        "product_link": GOOGLE + "&q=samsung galaxy s25",
        "immersive_product_page_token": "TOKEN123",
    }

def run_tests():
    print("1. Product rows keep a /go/ link")

    reset_state()
    SHOPPING["shopping_results"] = [sample_row()]
    rows = app.get_product_prices("samsung galaxy s25")
    check("one row returned", len(rows), 1)
    check("go link generated", rows[0]["go_link"], "/go/1234567890123456789")

    print("\\n2. /go resolves the merchant URL")

    reset_state()
    IMMERSIVE.update({
        "product_results": {
            "sellers_results": {
                "online_sellers": [
                    {
                        "name": "Flipkart",
                        "direct_link": "https://www.flipkart.com/p/item123",
                    }
                ]
            }
        }
    })

    client = app.app.test_client()
    response = client.get("/go/1234567890123456789?token=TOKEN123", follow_redirects=False)

    check("redirect status", response.status_code, 302)
    check(
        "redirect target",
        response.headers.get("Location"),
        "https://www.flipkart.com/p/item123",
    )
    print("\\n3. Merchant resolution is cached")

    reset_state()
    IMMERSIVE.update({
        "product_results": {
            "sellers_results": {
                "online_sellers": [
                    {
                        "name": "Flipkart",
                        "direct_link": "https://www.flipkart.com/p/item123",
                    }
                ]
            }
        }
    })

    client = app.app.test_client()

    first = client.get(
        "/go/1234567890123456789?token=TOKEN123",
        follow_redirects=False,
    )
    second = client.get(
        "/go/1234567890123456789?token=TOKEN123",
        follow_redirects=False,
    )

    immersive_calls = [
        c for c in _MockSearch.calls
        if c.get("engine") == "google_immersive_product"
    ]

    check("first redirect", first.status_code, 302)
    check("second redirect", second.status_code, 302)
    check("immersive called once", len(immersive_calls), 1)

    print("\\n4. Missing token falls back to Google Shopping")

    reset_state()
    client = app.app.test_client()

    response = client.get(
        "/go/1234567890123456789",
        follow_redirects=False,
    )

    check("fallback redirect", response.status_code, 302)
    check(
        "fallback host",
        response.headers.get("Location").startswith("https://www.google.com/search?tbm=shop"),
        True,
    )

    print("\\n5. Missing merchant link falls back cleanly")

    reset_state()
    IMMERSIVE.update({
        "product_results": {
            "sellers_results": {
                "online_sellers": [
                    {
                        "name": "Flipkart",
                        # no direct_link
                    }
                ]
            }
        }
    })

    client = app.app.test_client()

    response = client.get(
        "/go/1234567890123456789?token=TOKEN123",
        follow_redirects=False,
    )

    check("fallback when seller lacks link", response.status_code, 302)
    check(
        "google fallback used",
        response.headers.get("Location").startswith("https://www.google.com/search?tbm=shop"),
        True,
    )

    print("\\n6. Malformed immersive response does not crash")

    reset_state()
    IMMERSIVE.update({
        "product_results": {}
    })

    client = app.app.test_client()

    response = client.get(
        "/go/1234567890123456789?token=TOKEN123",
        follow_redirects=False,
    )

    check("malformed response fallback", response.status_code, 302)
    check(
        "still redirects somewhere",
        response.headers.get("Location").startswith("https://www.google.com/search?tbm=shop"),
        True,
    )

    print("\\n7. Google link with spaces still survives")

    reset_state()
    row = sample_row()
    row["product_link"] = GOOGLE + "&q=samsung galaxy s25 ultra 512gb"
    SHOPPING["shopping_results"] = [row]

    rows = app.get_product_prices("samsung galaxy s25 ultra 512gb")

    check("row kept despite raw spaces", len(rows), 1)
    check(
        "go link still present",
        rows[0]["go_link"],
        "/go/1234567890123456789",
    )
    print("\\n8. Merchant cache stores resolved URLs")

    reset_state()
    IMMERSIVE.update({
        "product_results": {
            "sellers_results": {
                "online_sellers": [
                    {
                        "name": "Flipkart",
                        "direct_link": "https://www.flipkart.com/p/item123",
                    }
                ]
            }
        }
    })

    client = app.app.test_client()

    client.get(
        "/go/1234567890123456789?token=TOKEN123",
        follow_redirects=False,
    )

    check(
        "merchant cache populated",
        app._merchant_cache.get("1234567890123456789"),
        "https://www.flipkart.com/p/item123",
    )

    print("\\n9. Missing product id returns fallback")

    reset_state()
    client = app.app.test_client()

    response = client.get(
        "/go/",
        follow_redirects=False,
    )

    check(
        "missing id handled",
        response.status_code in (301, 302, 404),
        True,
    )

    print("\\n10. Repeated lookups use cached merchant URL")

    reset_state()
    app._merchant_cache["1234567890123456789"] = "https://www.flipkart.com/p/item123"

    client = app.app.test_client()

    response = client.get(
        "/go/1234567890123456789?token=TOKEN123",
        follow_redirects=False,
    )

    immersive_calls = [
        c for c in _MockSearch.calls
        if c.get("engine") == "google_immersive_product"
    ]

    check("cached redirect", response.status_code, 302)
    check(
        "cached target",
        response.headers.get("Location"),
        "https://www.flipkart.com/p/item123",
    )
    check("no immersive call when cached", len(immersive_calls), 0)

    print("\\n11. Search results include go_link for every row")

    reset_state()
    SHOPPING["shopping_results"] = [
        sample_row(),
        {
            "product_id": "9876543210987654321",
            "title": "Samsung Galaxy S25 512GB",
            "price": "₹84,999",
            "source": "Croma",
            "thumbnail": "https://img.test/s25-512.jpg",
            "product_link": GOOGLE + "&q=samsung galaxy s25 512gb",
            "immersive_product_page_token": "TOKEN456",
        },
    ]

    rows = app.get_product_prices("samsung galaxy s25")

    check("two rows returned", len(rows), 2)
    check(
        "first go link",
        rows[0]["go_link"],
        "/go/1234567890123456789",
    )
    check(
        "second go link",
        rows[1]["go_link"],
        "/go/9876543210987654321",
    )

    if failures:
        print(f"\\nFAILURES ({len(failures)}):")
        for f in failures:
            print(" -", f)
        return 1

    print("\\nAll merchant link tests passed")
    return 0


if __name__ == "__main__":
    sys.exit(run_tests())