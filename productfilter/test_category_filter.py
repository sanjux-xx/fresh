"""Offline checks for the category filter.

No SerpApi key and no network: the fixtures below are shaped exactly like
`shopping_results` entries (title / price / store), and are drawn from the
kind of noise Google Shopping actually returns for these queries — the
accessories, lookalikes and flat-out wrong categories that used to reach the
page because laptops, fruits and groceries had no filter at all.

Run:  python3 test_category_filter.py
"""

import sys

import category_rules as cr


def P(title, store="Amazon.in"):
    return {"title": title, "store": store, "price": "₹999", "link": "https://x.test/1"}


# (slug, search term, [(product, should_be_kept)])
CASES = [
    # ---------------------------------------------------------------- mobiles
    ("mobiles", "iphone 16", [
        (P("Apple iPhone 16 (128GB) - Black", "Flipkart"), True),
        (P("Apple iPhone 16 Pro 256GB Natural Titanium", "Croma"), True),
        (P("Silicone Back Cover Case for iPhone 16", "Amazon.in"), False),
        (P("Tempered Glass Screen Protector for iPhone 16"), False),
        (P("Refurbished Apple iPhone 16 128GB", "Cashify"), False),
        (P("iPhone 16 Charger 20W Type-C Adapter"), False),
        (P("Apple MacBook Air M3 13 inch", "Croma"), False),      # other category
        (P("Apple iPhone 15 (128GB)", "Flipkart"), False),        # wrong model number
    ]),

    # ---------------------------------------------------------------- laptops
    ("laptops", "hp victus i5", [
        (P("HP Victus Gaming Laptop Intel Core i5 12450H 16GB", "Croma"), True),
        (P("HP Victus 15 i5 8GB 512GB SSD Laptop", "Reliance Digital"), True),
        (P("HP Victus Laptop Bag 15.6 inch"), False),
        (P("Laptop Cooling Pad for HP Victus"), False),
        (P("Apple iPhone 16 Pro Max 256GB", "Flipkart"), False),  # other category
        (P("Dell Inspiron i5 Laptop 16GB", "Dell"), False),       # term mismatch (hp/victus)
    ]),

    # -------------------------------------------------------------- groceries
    ("groceries", "atta 10kg", [
        (P("Aashirvaad Shudh Chakki Atta 10 kg", "BigBasket"), True),
        (P("Fortune Chakki Fresh Atta 10kg Pack", "JioMart"), True),
        (P("Atta Storage Container 10 kg Capacity"), False),
        (P("Stainless Steel Atta Kneader / Mixer"), False),
        (P("HP Laptop 15s Ryzen 5", "Croma"), False),             # other category
        (P("Aashirvaad Atta 5kg", "BigBasket"), False),           # wrong pack size
    ]),

    # ----------------------------------------------------------------- fruits
    ("fruits", "mango", [
        (P("Fresh Alphonso Mango 1 kg", "BigBasket"), True),
        (P("Banganapalli Mango 2 kg Box", "Blinkit"), True),
        (P("Real Mango Fruit Juice 1 L", "Zepto"), False),        # juice, not fruit
        (P("Artificial Mango Decorative Fruit Set"), False),
        (P("Mango Flavour Ice Cream 700 ml", "Zepto"), False),
        (P("Mango Pickle 500g", "JioMart"), False),
        (P("Apple iPhone 16 128GB", "Flipkart"), False),          # brand collision
        (P("Mango Tree Sapling Grafted Plant"), False),
    ]),

    # --------------------------------------------------------------- medicine
    ("medicine", "dolo 650", [
        (P("Dolo 650 Tablet - Strip of 15 Tablets", "1mg"), True),
        (P("Dolo 650mg Paracetamol Tablet", "PharmEasy"), True),
        (P("Samsung Galaxy Tab S9 Tablet 256GB", "Croma"), False),  # "tablet" the device
        (P("First Aid Box with Medicines"), False),
        (P("Dolo 500 Tablet Strip", "Netmeds"), False),             # wrong strength
    ]),
]


def main():
    failures = []
    checked = 0

    for slug, term, rows in CASES:
        cat = cr.get(slug)
        assert cat is not None, "unknown category in test: %s" % slug
        for product, expected in rows:
            checked += 1
            keep, reason = cr.explain(product, cat, term)
            if keep != expected:
                failures.append(
                    "[%s] %-52s expected %-6s got %-6s (%s)"
                    % (slug, product["title"][:52],
                       "KEEP" if expected else "DROP",
                       "KEEP" if keep else "DROP", reason)
                )

    # Cross-category leakage: run every fixture through every OTHER category.
    leaks = []
    for slug, term, rows in CASES:
        for product, expected in rows:
            if not expected:
                continue
            for other in cr.CATEGORIES:
                if other == slug:
                    continue
                # No search term: this asks the blunt question "could this
                # listing show up on the other category's page at all?"
                if cr.explain(product, cr.get(other), "")[0]:
                    leaks.append("%s listing '%s' also passes %s"
                                 % (slug, product["title"][:46], other))

    # Query building is per-category, not one generic string any more.
    print("Query templates")
    for slug, cat in cr.CATEGORIES.items():
        print("  %-10s base: %-40s term: %s"
              % (slug, cat.base_query, cat.build_query("xyz")))

    print("\nDetection from free-text homepage queries")
    for q, want in [("iphone 16 pro", "mobiles"), ("hp laptop i5", "laptops"),
                    ("aashirvaad atta 5kg", "groceries"), ("fresh banana", "fruits"),
                    ("crocin syrup", "medicine"), ("gift for dad", None)]:
        got = cr.detect_category(q)
        flag = "ok " if got == want else "FAIL"
        print("  %s %-24s -> %s" % (flag, q, got))
        if got != want:
            failures.append("detect_category(%r) = %r, wanted %r" % (q, got, want))

    print("\n%d listings checked across %d categories" % (checked, len(CASES)))
    if leaks:
        print("\nCROSS-CATEGORY LEAKS (%d):" % len(leaks))
        for l in leaks:
            print("  " + l)
    else:
        print("cross-category leakage: 0")

    if failures:
        print("\nFAILURES (%d):" % len(failures))
        for f in failures:
            print("  " + f)
        return 1

    print("all checks passed")
    return 0


if __name__ == "__main__":
    sys.exit(main())
