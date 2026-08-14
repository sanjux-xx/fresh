"""Regenerate the self-hosted webfonts in static/fonts/ (speed-test fix 03).

The 2026-08-13 speed test found fonts were 239.8 KB — 69.4% of first-load
weight — spread over seven woff2 files from fonts.gstatic.com, behind a
render-blocking stylesheet on a second origin. This script rebuilds them as
two self-hosted variable files totalling ~58 KB:

  * upstream source is the full variable TTF from google/fonts (not the
    per-subset woff2 Google serves, which would each be missing glyphs),
  * axes are clamped to the weights this app actually uses, and opsz/wdth are
    pinned, which is where most of the saving comes from,
  * the charset is subset to Latin-1 plus the typographic punctuation,
    currency (including ₹) and arrows the templates render.

Body text deliberately has no webfont: it uses the platform UI stack.

Run:  python3 build_fonts.py          (needs `pip install fonttools brotli`)

Then commit the regenerated static/fonts/*.woff2. Their URLs are content
hashed by static_url(), so a changed file busts its own cache.
"""

import os
import subprocess
import sys
import urllib.request

HERE = os.path.dirname(os.path.abspath(__file__))
OUT_DIR = os.path.join(HERE, "static", "fonts")

# Latin-1, the punctuation/arrows/currency the templates use, and U+FFFD.
# Deliberately excluded: Latin Extended, Vietnamese, Cyrillic, Greek — none of
# them are rendered by this app, and each one costs kilobytes on every visit.
# NOTE: Spline Sans Mono has no ₹ (U+20B9) glyph upstream, so the rupee sign in
# prices falls back to a system font. That was already true of the hosted
# Google version; it is not something this subset changed.
UNICODES = ",".join([
    "U+0020-007E",      # ASCII
    "U+00A0-00FF",      # Latin-1 supplement
    "U+0131", "U+0152-0153",
    "U+2013-2014",      # en/em dash
    "U+2018-201A", "U+201C-201E",   # smart quotes
    "U+2022", "U+2026", "U+2032-2033", "U+2039-203A",
    "U+20AC", "U+20B9",  # euro, rupee
    "U+2122",            # trademark
    "U+2190-2193",       # arrows
    "U+2212", "U+2215", "U+00D7",   # minus, slash, multiply
    "U+FFFD",
])

LAYOUT_FEATURES = "kern,liga,clig,calt,ccmp,locl,mark,mkmk,rlig"

# slug -> (upstream variable TTF, axis limits)
# A tuple limit keeps that axis variable within the range; a number pins it.
FONTS = {
    "bricolage-grotesque": (
        "https://raw.githubusercontent.com/google/fonts/main/ofl/"
        "bricolagegrotesque/BricolageGrotesque%5Bopsz,wdth,wght%5D.ttf",
        # Templates use 500 / 700 / 800. opsz and wdth are never varied.
        {"opsz": 24, "wdth": 100, "wght": (500, 800)},
    ),
    "spline-sans-mono": (
        "https://raw.githubusercontent.com/google/fonts/main/ofl/"
        "splinesansmono/SplineSansMono%5Bwght%5D.ttf",
        # Templates use 400 / 500 / 600.
        {"wght": (400, 600)},
    ),
}


def fetch(url, dest):
    req = urllib.request.Request(url, headers={"User-Agent": "build_fonts"})
    with urllib.request.urlopen(req, timeout=60) as resp:
        data = resp.read()
    with open(dest, "wb") as handle:
        handle.write(data)
    return len(data)


def build(slug, url, limits):
    from fontTools.ttLib import TTFont
    from fontTools.varLib import instancer

    src = os.path.join("/tmp", slug + "-upstream.ttf")
    raw = fetch(url, src)

    font = TTFont(src)
    limited = instancer.instantiateVariableFont(font, limits, inplace=False)
    pinned = os.path.join("/tmp", slug + "-limited.ttf")
    limited.save(pinned)

    out = os.path.join(OUT_DIR, slug + ".woff2")
    subprocess.run([
        sys.executable, "-m", "fontTools.subset", pinned,
        "--unicodes=" + UNICODES,
        "--layout-features=" + LAYOUT_FEATURES,
        "--flavor=woff2", "--no-hinting", "--desubroutinize",
        "--name-IDs=1,2,3,4,5,6",
        "--output-file=" + out,
    ], check=True)

    size = os.path.getsize(out)
    print("%-24s %7d B upstream -> %6d B woff2  (%.1f%% of source)"
          % (slug, raw, size, 100.0 * size / raw))
    return size


def main():
    if not os.path.isdir(OUT_DIR):
        os.makedirs(OUT_DIR)
    total = sum(build(slug, url, limits)
                for slug, (url, limits) in sorted(FONTS.items()))
    print("-" * 62)
    print("total font payload: %d B (%.1f KB) — was 239.8 KB over 7 files"
          % (total, total / 1024.0))
    return 0


if __name__ == "__main__":
    sys.exit(main())
