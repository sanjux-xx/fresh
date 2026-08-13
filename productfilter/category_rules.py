"""One declarative registry describing what belongs in each category.

Why this exists
---------------
The category route used to filter with two hand-written functions: a
phone-only filter for /category/mobiles and a pharmacy filter for
/category/medicine. Laptops, groceries and fruits had no filter at all, so
whatever Google Shopping returned for "grocery items" (storage racks, kitchen
gadgets, a phone case) was rendered as a grocery. Worse, the phone filter
ended with `return filtered if filtered else products` — when it removed
everything it silently handed back the unfiltered list, so it looked like it
worked while doing nothing.

Everything a category needs now lives in one CATEGORIES table, and a single
matcher reads it. Adding a category is a data edit, not new control flow.

The two term lists are deliberately different things:

  signals    — terms that mean "this listing plausibly belongs here".
               Used to ACCEPT. Broad, overlapping across categories is fine.
  exclusive  — the subset that means "this listing belongs ONLY here".
               Every OTHER category automatically blocks these, which is what
               keeps a laptop out of /category/groceries.

Terms that read as two categories at once ("tablet" is a pill and a device,
"ml" is a dose and a bottle of oil, "apple" is a fruit and a phone brand) stay
out of `exclusive` on purpose — blocking on them causes wrong removals, which
are harder to notice than wrong additions.
"""

import re

# ---------------------------------------------------------------------------
# Shared junk: never a real product listing in ANY category.
# ---------------------------------------------------------------------------
# Accessories and lookalikes ride along on almost every Google Shopping query
# ("iPhone 16 case" for a phone search, "artificial mango" for fruit).
ACCESSORY_BLOCK = (
    "case", "back cover", "flip cover", "pouch", "skin", "sleeve",
    "tempered", "screen protector", "screen guard",
    "charger", "charging cable", "data cable", "adapter", "power bank",
    "holder", "stand", "mount", "tripod", "grip",
    "sticker", "decal", "poster", "wallpaper", "keychain",
    "dummy", "replica", "toy", "miniature", "showpiece", "artificial",
)

# Second-hand / not-a-purchase listings.
RESALE_BLOCK = (
    "used", "second hand", "secondhand", "pre owned", "pre-owned",
    "refurbished", "renewed", "open box", "exchange offer",
    "sell your", "selling", "repair", "service centre", "service center",
    "spare part", "spares", "replacement part",
)

# Words that signal the page is about a product rather than the product.
CONTENT_BLOCK = ("ebook", "e-book", "paperback", "hardcover", "magazine", "course")

STOPWORDS = {
    "the", "a", "an", "and", "or", "of", "for", "with", "in", "on", "at",
    "to", "by", "buy", "online", "india", "price", "prices", "best", "top",
    "new", "latest", "cheap", "cheapest", "offer", "offers", "deal", "deals",
    "sale", "shop", "store", "get", "order", "near", "me", "all", "any",
}

# "1 kg", "500g", "2 x 500 ml", "6 pcs", "1 dozen", "family pack"
PACK_UNIT_RE = re.compile(
    r"\b\d+\s?(?:kg|kgs|g|gm|gms|gram|grams|mg|ml|l|ltr|litre|litres|liter|liters"
    r"|pc|pcs|piece|pieces|dozen|pack|packet|sachet|combo|count|n)\b"
)
# "128GB", "8 GB RAM", "15.6 inch", "5000mAh", "144Hz", "i7", "512 SSD"
TECH_SPEC_RE = re.compile(
    r"\b(?:\d+\s?(?:gb|tb|mb|mah|inch|hz|w|mp)|i[3579]|ryzen\s?\d|m[1-4]\s?(?:pro|max)?)\b"
)
# "500mg", "10 ml syrup", "10's", "strip of 15"
DOSE_RE = re.compile(r"\b(?:\d+\s?(?:mg|mcg|iu|ml)|strip of \d+|\d+\s?tablets?|\d+\s?capsules?)\b")


class Category:
    """Everything the matcher needs to judge one category."""

    def __init__(self, slug, label, base_query, query_template,
                 signals=(), exclusive=(), stores=(), blocks=(),
                 unit_re=None, require=("signal_or_store",)):
        self.slug = slug
        self.label = label
        # Query sent to SerpApi when the shopper has typed nothing.
        self.base_query = base_query
        # Query template used when they have. "{term}" is their input.
        self.query_template = query_template
        self.signals = tuple(signals)
        self.exclusive = tuple(exclusive)
        self.stores = tuple(stores)
        # Category-specific junk, on top of the shared block lists.
        self.blocks = tuple(blocks)
        # Optional pattern that a title must satisfy (pack size, spec, dose).
        self.unit_re = unit_re
        self.require = tuple(require)

    def build_query(self, term=""):
        term = (term or "").strip()

        if not term:
            return self.base_query

        if "{term}" not in self.query_template:
            return term

        built = self.query_template.format(term=term).strip()

        seen = set()
        words = []

        for word in built.split():
            key = word.lower()
            if key in seen:
                continue
            seen.add(key)
            words.append(word)

        return " ".join(words)

CATEGORIES = {
    # -----------------------------------------------------------------
    "mobiles": Category(
        slug="mobiles",
        label="Mobiles",
        base_query="smartphone",
        query_template="{term}",
        signals=(
            "smartphone", "mobile phone", "cellphone", "iphone", "galaxy",
            "redmi", "realme", "oneplus", "vivo", "oppo", "poco", "pixel",
            "nothing phone", "moto ", "motorola", "infinix", "tecno", "lava",
            "5g", "4g", "dual sim",
        ),
        exclusive=("smartphone", "iphone", "cellphone", "mobile phone"),
        stores=("amazon", "flipkart", "croma", "reliance digital", "vijay sales",
                "tatacliq", "sangeetha", "poorvika", "samsung", "apple", "oneplus",
                "mi ", "xiaomi", "realme", "vivo", "oppo"),
        blocks=("smart watch", "smartwatch", "earbuds", "neckband", "feature phone",
                "landline", "keypad phone", "phone holder", "sim card", "recharge"),
        unit_re=TECH_SPEC_RE,
    ),

    # -----------------------------------------------------------------
    "laptops": Category(
        slug="laptops",
        label="Laptops",
        base_query="laptop price India",
        query_template="{term} laptop price India",
        signals=(
            "laptop", "notebook", "macbook", "chromebook", "ultrabook",
            "thinkpad", "ideapad", "vivobook", "zenbook", "inspiron", "latitude",
            "pavilion", "victus", "omen", "nitro", "aspire", "legion", "rog ",
            "tuf ", "gaming laptop", "i3", "i5", "i7", "i9", "ryzen",
        ),
        exclusive=("laptop", "macbook", "chromebook", "ultrabook", "notebook pc"),
        stores=("amazon", "flipkart", "croma", "reliance digital", "vijay sales",
                "tatacliq", "hp", "dell", "lenovo", "asus", "acer", "apple"),
        blocks=("laptop bag", "laptop sleeve", "laptop table", "laptop stand",
                "laptop skin", "cooling pad", "docking station", "keyboard cover",
                "ram module", "ssd only", "battery for", "charger for"),
        unit_re=TECH_SPEC_RE,
    ),

    # -----------------------------------------------------------------
    "groceries": Category(
        slug="groceries",
        label="Groceries",
        base_query="grocery staples pack price India",
        query_template="{term} grocery pack price India",
        signals=(
            "atta", "flour", "rice", "basmati", "dal", "pulses", "toor", "moong",
            "chana", "rajma", "sugar", "salt", "oil", "sunflower", "mustard oil",
            "ghee", "milk", "curd", "paneer", "butter", "cheese", "bread",
            "biscuit", "cookies", "namkeen", "snack", "tea", "coffee", "masala",
            "spice", "turmeric", "haldi", "chilli", "jeera", "cumin", "poha",
            "suji", "besan", "maida", "noodles", "pasta", "sauce", "ketchup",
            "jam", "honey", "pickle", "detergent", "soap", "shampoo", "toothpaste",
            "sanitizer", "tissue", "cleaner",
        ),
        exclusive=("atta", "basmati", "namkeen", "detergent", "toothpaste",
                   "poha", "besan", "haldi"),
        stores=("bigbasket", "jiomart", "blinkit", "zepto", "instamart", "dunzo",
                "dmart", "amazon", "flipkart", "grofers", "otipy", "licious"),
        blocks=("container", "storage box", "jar set", "dispenser", "rack",
                "trolley", "grinder", "mixer", "cooker", "kadai", "utensil",
                "recipe", "cookbook", "seeds for planting"),
        unit_re=PACK_UNIT_RE,
        require=("signal", "unit_or_store"),
    ),

    # -----------------------------------------------------------------
    "fruits": Category(
        slug="fruits",
        label="Fruits",
        base_query="fresh fruits 1kg buy online India",
        query_template="fresh {term} fruit buy online India",
        signals=(
            "apple", "banana", "mango", "orange", "grapes", "papaya", "guava",
            "pomegranate", "watermelon", "muskmelon", "pineapple", "kiwi",
            "pear", "peach", "plum", "litchi", "lychee", "chikoo", "sapota",
            "strawberry", "blueberry", "cherry", "avocado", "dragon fruit",
            "custard apple", "jackfruit", "sweet lime", "mosambi", "coconut",
            "fresh fruit", "fruits",
        ),
        # Fruit names double as brands ("Apple", "BlackBerry") and flavours, so
        # only the unmistakably-produce ones are exclusive.
        exclusive=("banana", "papaya", "guava", "pomegranate", "watermelon",
                   "muskmelon", "chikoo", "sapota", "mosambi", "jackfruit"),
        stores=("bigbasket", "blinkit", "zepto", "instamart", "jiomart", "dunzo",
                "otipy", "amazon fresh", "dmart", "licious", "farmers"),
        blocks=("juice", "juicer", "squash", "syrup", "candy", "flavour", "flavor",
                "essence", "dried", "freeze dried", "powder", "extract",
                "seeds", "sapling", "plant", "tree", "basket", "bowl", "peeler",
                "cutter", "slicer", "scented", "fragrance", "soap", "face wash",
                "iphone", "macbook", "airpods", "watch", "laptop", "vinegar",
                # Processed-fruit products: a mango pickle is a grocery, not a
                # mango, and it outranks real produce on Google Shopping.
                "jam", "murabba", "pickle", "chutney", "puree", "pulp",
                "concentrate", "canned", "tinned", "chips", "wafer"),
        unit_re=PACK_UNIT_RE,
        require=("signal", "unit_or_store"),
    ),

    # -----------------------------------------------------------------
    "medicine": Category(
        slug="medicine",
        label="Medicine",
        base_query="common medicines buy online India",
        query_template="{term} medicine buy online India",
        signals=(
            "tablet", "tablets", "capsule", "syrup", "suspension", "drops",
            "cream", "gel", "ointment", "injection", "sachet", "strip",
            "inhaler", "spray", "lotion", "medicine", "pharma", "healthcare",
            "supplement", "vitamin", "protein", "antibiotic", "antacid",
            "paracetamol", "ibuprofen", "relief", "mg", "ml",
        ),
        exclusive=("capsule", "syrup", "suspension", "ointment", "inhaler",
                   "antibiotic", "antacid", "paracetamol", "ibuprofen", "pharma"),
        stores=("1mg", "netmeds", "pharmeasy", "apollo", "medplus", "truemeds",
                "flipkart health", "wellness forever", "zeelab"),
        blocks=("mobile", "phone", "laptop", "tablet pc", "ipad", "headphone",
                "earphone", "camera", "shirt", "shoe", "furniture",
                "first aid box", "pill box", "organizer"),
        unit_re=DOSE_RE,
    ),
}


def get(slug):
    return CATEGORIES.get((slug or "").strip().lower())


def _blocked_terms(cat):
    """Shared junk + this category's own blocks + every OTHER category's
    exclusive terms. The last part is what enforces category separation."""
    terms = set(ACCESSORY_BLOCK) | set(RESALE_BLOCK) | set(CONTENT_BLOCK)
    terms |= set(cat.blocks)
    for other in CATEGORIES.values():
        if other.slug != cat.slug:
            terms |= set(other.exclusive)
    # A term the category itself claims must never be blocked, even if another
    # category calls it exclusive (e.g. medicine "drops" vs nothing else).
    return terms - set(cat.signals)


def _tokens(text):
    return [t for t in re.findall(r"[a-z0-9]+", (text or "").lower())
            if len(t) > 1 and t not in STOPWORDS]


def matches_search_term(title, term):
    """Does this listing actually answer what the shopper typed?

    Numeric-bearing tokens ("16", "128gb", "500mg") must all appear — those are
    the model number and the size, and getting them wrong shows the wrong
    product. Word tokens need a majority match, which tolerates stores that
    reorder or drop a descriptor.
    """
    wanted = _tokens(term)
    if not wanted:
        return True

    hay = " " + re.sub(r"[^a-z0-9]+", " ", (title or "").lower()) + " "
    hay_compact = hay.replace(" ", "")

    numeric = [t for t in wanted if any(c.isdigit() for c in t)]
    words = [t for t in wanted if t not in numeric]

    for t in numeric:
        if (" %s " % t) not in hay and t not in hay_compact:
            return False

    if not words:
        return True
    hits = sum(1 for t in words if (" %s " % t) in hay or t in hay_compact)
    return hits >= max(1, (len(words) + 1) // 2)


def explain(product, cat, term=""):
    """Judge one listing. Returns (keep: bool, reason: str)."""
    title = (product.get("title") or "").lower()
    store = (product.get("store") or "").lower()

    if not title:
        return False, "no title"

    for bad in _blocked_terms(cat):
        if bad in title:
            return False, "blocked term: %s" % bad

    has_signal = any(s in title for s in cat.signals)
    has_store = bool(store) and any(s in store for s in cat.stores)
    has_unit = bool(cat.unit_re and cat.unit_re.search(title))

    for rule in cat.require:
        if rule == "signal" and not has_signal:
            return False, "no %s signal in title" % cat.slug
        if rule == "signal_or_store" and not (has_signal or has_store):
            return False, "no %s signal and store not a %s seller" % (cat.slug, cat.slug)
        if rule == "unit_or_store" and not (has_unit or has_store):
            return False, "no pack size and store not a %s seller" % cat.slug

    if not matches_search_term(title, term):
        return False, "does not match search term"

    return True, "ok"


def filter_products(products, slug, term=""):
    """Keep only the listings that belong in this category.

    Returns (kept, removed_count). There is deliberately NO fallback to the
    unfiltered list: a category page that shows nothing is honest, a category
    page that shows a phone under Fruits is not.
    """
    cat = get(slug)
    if not cat or not products:
        return products, 0

    kept = [p for p in products if explain(p, cat, term)[0]]
    return kept, len(products) - len(kept)


# Order matters: the first category whose exclusive term appears wins, so the
# unambiguous ones are checked before the ones with shared vocabulary.
_DETECT_ORDER = ("medicine", "laptops", "mobiles", "fruits", "groceries")


def detect_category(query):
    """Best guess at which category a free-text homepage search belongs to.

    Only fires on `exclusive` terms — the unambiguous ones. A vague query like
    "gift for dad" correctly detects nothing and stays unfiltered.
    """
    q = " " + re.sub(r"[^a-z0-9]+", " ", (query or "").lower()) + " "
    for slug in _DETECT_ORDER:
        cat = CATEGORIES[slug]
        for term in cat.exclusive:
            if (" %s " % term.strip()) in q or term.strip() in q:
                return slug
    return None
