from flask import Blueprint, render_template, request
from serpapi import GoogleSearch
import os
import re
import time
import logging
import socket

import trustscan

# ===============================
# BLUEPRINT
# ===============================
food_bp = Blueprint("food", __name__, url_prefix="/food")


@food_bp.app_template_filter("slugify")
def _slugify_filter(text):
    """Expose slugify to templates so menu links match the item routes."""
    return slugify(text)

# ===============================
# CACHE
# ===============================
food_cache = {}
FOOD_CACHE_TTL = 30 * 60  # 30 minutes

# ===============================
# MENU DATA
# ===============================
FOOD_DATA = {
    "mcdonalds": {
        "name": "McDonald's",
        "menu": {
            "Burgers": [
                "McAloo Tikki",
                "McVeggie",
                "McChicken",
                "Maharaja Mac",
                "McSpicy Paneer",
                "McSpicy Chicken",
                "Big Spicy Paneer Wrap",
            ],
            "Sides & Snacks": [
                "French Fries (Small)",
                "French Fries (Medium)",
                "French Fries (Large)",
                "Chicken McNuggets (6pc)",
                "Chicken McNuggets (9pc)",
                "Veg Pizza McPuff",
            ],
            "Beverages": [
                "Coke (Small)",
                "Coke (Medium)",
                "Coke (Large)",
                "McCafe Cappuccino",
                "McCafe Latte",
                "Shamrock Shake",
            ],
            "Desserts": [
                "McFlurry Oreo",
                "Soft Serve Cone",
                "Chocolate Shake",
            ],
            "Meals": [
                "McAloo Tikki Meal",
                "McChicken Meal",
                "Maharaja Mac Meal",
            ],
        },
        "prices": {
            "McAloo Tikki":            {"official": 45,  "swiggy": 55,  "zomato": 52},
            "McVeggie":                {"official": 129, "swiggy": 139, "zomato": 135},
            "McChicken":               {"official": 139, "swiggy": 149, "zomato": 145},
            "Maharaja Mac":            {"official": 229, "swiggy": 249, "zomato": 239},
            "McSpicy Paneer":          {"official": 179, "swiggy": 199, "zomato": 189},
            "McSpicy Chicken":         {"official": 189, "swiggy": 209, "zomato": 199},
            "Big Spicy Paneer Wrap":   {"official": 169, "swiggy": 189, "zomato": 179},
            "French Fries (Small)":    {"official": 59,  "swiggy": 69,  "zomato": 65},
            "French Fries (Medium)":   {"official": 99,  "swiggy": 109, "zomato": 105},
            "French Fries (Large)":    {"official": 129, "swiggy": 139, "zomato": 135},
            "Chicken McNuggets (6pc)": {"official": 179, "swiggy": 199, "zomato": 189},
            "Chicken McNuggets (9pc)": {"official": 259, "swiggy": 279, "zomato": 269},
            "Veg Pizza McPuff":        {"official": 49,  "swiggy": 59,  "zomato": 55},
            "Coke (Small)":            {"official": 49,  "swiggy": 59,  "zomato": 55},
            "Coke (Medium)":           {"official": 69,  "swiggy": 79,  "zomato": 75},
            "Coke (Large)":            {"official": 89,  "swiggy": 99,  "zomato": 95},
            "McCafe Cappuccino":       {"official": 129, "swiggy": 149, "zomato": 139},
            "McCafe Latte":            {"official": 119, "swiggy": 139, "zomato": 129},
            "Shamrock Shake":          {"official": 99,  "swiggy": 119, "zomato": 109},
            "McFlurry Oreo":           {"official": 119, "swiggy": 139, "zomato": 129},
            "Soft Serve Cone":         {"official": 49,  "swiggy": 59,  "zomato": 55},
            "Chocolate Shake":         {"official": 129, "swiggy": 149, "zomato": 139},
            "McAloo Tikki Meal":       {"official": 149, "swiggy": 169, "zomato": 159},
            "McChicken Meal":          {"official": 229, "swiggy": 249, "zomato": 239},
            "Maharaja Mac Meal":       {"official": 319, "swiggy": 339, "zomato": 329},
        },
        "buy_links": {
            "official": "https://mcdelivery.co.in/menu",
            "swiggy":   "https://www.swiggy.com/search?query=mcdonalds",
            "zomato":   "https://www.zomato.com/search?q=mcdonalds",
        }
    },

    "pizzahut": {
        "name": "Pizza Hut",
        "menu": {
            "Pizzas (Personal)": [
                "Margherita Personal",
                "Cheese & Tomato Personal",
                "Veggie Supreme Personal",
                "Chicken Supreme Personal",
                "Pepperoni Personal",
            ],
            "Pizzas (Medium)": [
                "Margherita Medium",
                "Double Cheese Margherita Medium",
                "Veggie Supreme Medium",
                "Chicken Supreme Medium",
                "BBQ Chicken Medium",
            ],
            "Pizzas (Large)": [
                "Margherita Large",
                "Veggie Supreme Large",
                "Chicken Supreme Large",
                "BBQ Chicken Large",
            ],
            "Sides": [
                "Garlic Bread",
                "Stuffed Garlic Bread",
                "Chicken Wings (6pc)",
                "Potato Wedges",
                "Coleslaw",
            ],
            "Beverages": [
                "Pepsi (300ml)",
                "Pepsi (500ml)",
                "7UP (300ml)",
            ],
            "Desserts": [
                "Choco Lava Cake",
                "Mango Cheesecake",
            ],
        },
        "prices": {
            "Margherita Personal":             {"official": 149, "swiggy": 169, "zomato": 159},
            "Cheese & Tomato Personal":        {"official": 169, "swiggy": 189, "zomato": 179},
            "Veggie Supreme Personal":         {"official": 199, "swiggy": 219, "zomato": 209},
            "Chicken Supreme Personal":        {"official": 229, "swiggy": 249, "zomato": 239},
            "Pepperoni Personal":              {"official": 249, "swiggy": 269, "zomato": 259},
            "Margherita Medium":               {"official": 299, "swiggy": 329, "zomato": 319},
            "Double Cheese Margherita Medium": {"official": 349, "swiggy": 379, "zomato": 369},
            "Veggie Supreme Medium":           {"official": 399, "swiggy": 429, "zomato": 419},
            "Chicken Supreme Medium":          {"official": 449, "swiggy": 479, "zomato": 469},
            "BBQ Chicken Medium":              {"official": 469, "swiggy": 499, "zomato": 489},
            "Margherita Large":                {"official": 449, "swiggy": 489, "zomato": 469},
            "Veggie Supreme Large":            {"official": 549, "swiggy": 589, "zomato": 569},
            "Chicken Supreme Large":           {"official": 649, "swiggy": 689, "zomato": 669},
            "BBQ Chicken Large":               {"official": 699, "swiggy": 739, "zomato": 719},
            "Garlic Bread":                    {"official": 99,  "swiggy": 119, "zomato": 109},
            "Stuffed Garlic Bread":            {"official": 149, "swiggy": 169, "zomato": 159},
            "Chicken Wings (6pc)":             {"official": 199, "swiggy": 219, "zomato": 209},
            "Potato Wedges":                   {"official": 99,  "swiggy": 119, "zomato": 109},
            "Coleslaw":                        {"official": 59,  "swiggy": 79,  "zomato": 69},
            "Pepsi (300ml)":                   {"official": 49,  "swiggy": 59,  "zomato": 55},
            "Pepsi (500ml)":                   {"official": 69,  "swiggy": 79,  "zomato": 75},
            "7UP (300ml)":                     {"official": 49,  "swiggy": 59,  "zomato": 55},
            "Choco Lava Cake":                 {"official": 99,  "swiggy": 119, "zomato": 109},
            "Mango Cheesecake":                {"official": 129, "swiggy": 149, "zomato": 139},
        },
        "buy_links": {
            "official": "https://www.pizzahut.co.in/orderonline",
            "swiggy":   "https://www.swiggy.com/search?query=pizza+hut",
            "zomato":   "https://www.zomato.com/search?q=pizza+hut",
        }
    },

    "dominos": {
        "name": "Domino's",
        "menu": {
            "Pizzas (Regular)": [
                "Margherita Regular",
                "Double Cheese Margherita Regular",
                "Peppy Paneer Regular",
                "Chicken Dominator Regular",
                "Keema Do Pyaza Regular",
            ],
            "Pizzas (Medium)": [
                "Margherita Medium",
                "Double Cheese Margherita Medium",
                "Peppy Paneer Medium",
                "Chicken Dominator Medium",
                "Farmhouse Medium",
            ],
            "Pizzas (Large)": [
                "Margherita Large",
                "Peppy Paneer Large",
                "Chicken Dominator Large",
                "Farmhouse Large",
                "Veg Extravaganza Large",
            ],
            "Sides": [
                "Garlic Breadsticks",
                "Stuffed Garlic Bread",
                "Chicken Wings",
                "Pasta Italiana White",
                "Pasta Italiana Red",
            ],
            "Beverages": [
                "Coke (300ml)",
                "Coke (500ml)",
                "Sprite (300ml)",
                "Fanta (300ml)",
            ],
            "Desserts": [
                "Choco Lava Cake",
                "Butterscotch Mousse Cake",
            ],
        },
        "prices": {
            "Margherita Regular":               {"official": 149, "swiggy": 169, "zomato": 159},
            "Double Cheese Margherita Regular": {"official": 199, "swiggy": 219, "zomato": 209},
            "Peppy Paneer Regular":             {"official": 219, "swiggy": 239, "zomato": 229},
            "Chicken Dominator Regular":        {"official": 269, "swiggy": 289, "zomato": 279},
            "Keema Do Pyaza Regular":           {"official": 249, "swiggy": 269, "zomato": 259},
            "Margherita Medium":                {"official": 249, "swiggy": 279, "zomato": 269},
            "Double Cheese Margherita Medium":  {"official": 299, "swiggy": 329, "zomato": 319},
            "Peppy Paneer Medium":              {"official": 349, "swiggy": 379, "zomato": 369},
            "Chicken Dominator Medium":         {"official": 399, "swiggy": 429, "zomato": 419},
            "Farmhouse Medium":                 {"official": 379, "swiggy": 409, "zomato": 399},
            "Margherita Large":                 {"official": 399, "swiggy": 439, "zomato": 419},
            "Peppy Paneer Large":               {"official": 549, "swiggy": 589, "zomato": 569},
            "Chicken Dominator Large":          {"official": 649, "swiggy": 689, "zomato": 669},
            "Farmhouse Large":                  {"official": 599, "swiggy": 639, "zomato": 619},
            "Veg Extravaganza Large":           {"official": 649, "swiggy": 689, "zomato": 669},
            "Garlic Breadsticks":               {"official": 99,  "swiggy": 119, "zomato": 109},
            "Stuffed Garlic Bread":             {"official": 149, "swiggy": 169, "zomato": 159},
            "Chicken Wings":                    {"official": 179, "swiggy": 199, "zomato": 189},
            "Pasta Italiana White":             {"official": 149, "swiggy": 169, "zomato": 159},
            "Pasta Italiana Red":               {"official": 149, "swiggy": 169, "zomato": 159},
            "Coke (300ml)":                     {"official": 49,  "swiggy": 59,  "zomato": 55},
            "Coke (500ml)":                     {"official": 69,  "swiggy": 79,  "zomato": 75},
            "Sprite (300ml)":                   {"official": 49,  "swiggy": 59,  "zomato": 55},
            "Fanta (300ml)":                    {"official": 49,  "swiggy": 59,  "zomato": 55},
            "Choco Lava Cake":                  {"official": 109, "swiggy": 129, "zomato": 119},
            "Butterscotch Mousse Cake":         {"official": 99,  "swiggy": 119, "zomato": 109},
        },
        "buy_links": {
            "official": "https://www.dominos.co.in/menu",
            "swiggy":   "https://www.swiggy.com/search?query=dominos",
            "zomato":   "https://www.zomato.com/search?q=dominos",
        }
    },
}


# ===============================
# HELPERS
# ===============================
def slugify(text: str) -> str:
    """Robust slug generator — handles special chars, spaces, hyphens."""
    text = text.lower()
    text = re.sub(r"[^a-z0-9\s-]", "", text)
    text = re.sub(r"[-\s]+", "-", text.strip())
    return text

def item_to_slug(item: str) -> str:
    return slugify(item)

def slug_to_item(slug: str) -> str:
    return slug.replace("-", " ").title()


# ===============================
# LIVE PRICE FETCHER — SerpAPI
# ===============================
def get_prices_for_item(brand_key, item_name):
    """
    Fetch live prices via SerpAPI Google Shopping.
    Falls back to hardcoded prices if SerpAPI returns nothing.
    """
    brand      = FOOD_DATA.get(brand_key, {})
    brand_name = brand.get("name", "")
    base       = brand.get("prices", {}).get(item_name, {})

    # ── Check cache first ──
    cache_key = f"food_{brand_key}_{item_name}".lower().strip()
    now = time.time()
    if cache_key in food_cache:
        data, ts = food_cache[cache_key]
        if now - ts < FOOD_CACHE_TTL:
            return data

    item_query  = item_name.replace(" ", "+")
    brand_query = brand_name.replace(" ", "+")

    # ── Start with hardcoded fallback ──
    prices = {
        "official": base.get("official"),
        "swiggy":   base.get("swiggy"),
        "zomato":   base.get("zomato"),
    }
    buy_links = {
        "official": brand.get("buy_links", {}).get("official", "#"),
        "swiggy":   f"https://www.swiggy.com/search?query={item_query}+{brand_query}",
        "zomato":   f"https://www.zomato.com/search?q={item_query}+{brand_query}",
    }

    # ── Try SerpAPI for live prices + real links ──
    _prev_timeout = socket.getdefaulttimeout()
    try:
        socket.setdefaulttimeout(20)
        params = {
            "engine":   "google_shopping",
            "q":        f"{item_name} {brand_name} price India",
            "location": "India",
            "hl":       "en",
            "gl":       "in",
            "api_key":  os.getenv("SERPAPI_KEY")
        }
        results = GoogleSearch(params).get_dict()

        for item in results.get("shopping_results", []):
            source    = item.get("source", "").lower()
            price_str = item.get("price", "")
            link      = item.get("link") or item.get("product_link") or ""

            if link.startswith("/"):
                link = "https://www.google.com" + link
            if not link.startswith("http"):
                link = f"https://www.google.com/search?tbm=shop&q={item_query}+{brand_query}"

            try:
                price = int(float(price_str.replace("₹", "").replace(",", "").strip()))
            except:
                continue

            if "swiggy" in source and not prices["swiggy"]:
                prices["swiggy"]    = price
                buy_links["swiggy"] = link

            elif "zomato" in source and not prices["zomato"]:
                prices["zomato"]    = price
                buy_links["zomato"] = link

            elif any(x in source for x in ["mcdonald", "pizza hut", "domino", "official"]) \
                 and not prices["official"]:
                prices["official"]    = price
                buy_links["official"] = link

    except Exception as e:
        logging.error(f"SerpAPI food error: {e}")
    finally:
        socket.setdefaulttimeout(_prev_timeout)

    # ── TrustScan: never hand out a low-trust merchant link ──
    # SerpApi occasionally returns a reseller or aggregator link instead of the
    # platform itself. Anything scoring at or below the threshold is discarded
    # and the platform's own safe search URL is used instead.
    safe_links = {
        "official": brand.get("buy_links", {}).get("official", "#"),
        "swiggy":   f"https://www.swiggy.com/search?query={item_query}+{brand_query}",
        "zomato":   f"https://www.zomato.com/search?q={item_query}+{brand_query}",
    }
    trust = {}
    if trustscan.ENABLED:
        try:
            scored = trustscan.score_urls([
                {"url": buy_links[k], "store": k} for k in buy_links
                if buy_links[k] and buy_links[k] != "#"
            ])
            for k, link in list(buy_links.items()):
                res = scored.get(link)
                trust[k] = res or {}
                if res and not trustscan.is_trusted(res):
                    logging.info("TrustScan dropped food link for %s (%s): %s",
                                 k, res.get("score"), link)
                    buy_links[k] = safe_links[k]
        except Exception as e:
            logging.error(f"TrustScan food error: {e}")

    result = {"prices": prices, "buy_links": buy_links, "trust": trust}
    food_cache[cache_key] = (result, now)
    return result


# ===============================
# ROUTES
# ===============================

def brand_summary():
    """Brand cards for the picker, driven by FOOD_DATA rather than hardcoded
    links in the template — adding a brand to the data now adds a card."""
    icons = {"mcdonalds": "🍟", "pizzahut": "🍕", "dominos": "🍕", "kfc": "🍗",
             "burgerking": "🍔", "subway": "🥪", "starbucks": "☕"}
    out = {}
    for key, data in FOOD_DATA.items():
        out[key] = {
            "name": data.get("name", key.title()),
            "icon": icons.get(key, "🍽️"),
            "count": len(data.get("prices", {})),
        }
    return out


@food_bp.route("/")
def food_home():
    return render_template("food.html", brands=brand_summary())


@food_bp.route("/<brand>")
def food_brand_page(brand):
    brand_data = FOOD_DATA.get(brand)
    if not brand_data:
        return render_template("food.html", brands=brand_summary(),
                               error=f"Brand '{brand}' not found."), 404

    return render_template(
        "food_brand.html",
        brand_name=brand_data["name"],
        brand_key=brand,
        icon=brand_summary().get(brand, {}).get("icon", "🍔"),
        menu=brand_data["menu"],
    )


@food_bp.route("/<brand>/<item_slug>")
def food_item_page(brand, item_slug):
    brand_data = FOOD_DATA.get(brand)
    if not brand_data:
        return render_template("food.html", brands=brand_summary(),
                               error="Brand not found."), 404

    # ── Robust slug matching using slugify ──
    all_items = [i for items in brand_data["menu"].values() for i in items]
    matched   = next((i for i in all_items if slugify(i) == item_slug.lower()), None)

    if not matched:
        return render_template(
            "food_brand.html",
            brand_name=brand_data["name"],
            brand_key=brand,
            icon=brand_summary().get(brand, {}).get("icon", "🍔"),
            menu=brand_data["menu"],
            error="That item isn't on this menu."
        ), 404

    item_name = matched
    city      = request.args.get("city", "bangalore").lower()

    # ── Get live prices + links (fallback to hardcoded) ──
    data      = get_prices_for_item(brand, item_name)
    prices    = data["prices"]
    buy_links = data["buy_links"]

    return render_template(
        "food_item.html",
        item_name=item_name,
        brand=brand,
        brand_name=brand_data["name"],
        prices=prices,
        buy_links=buy_links,
        trust=data.get("trust", {}),
        city=city,
    )