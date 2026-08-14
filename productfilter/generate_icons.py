"""Generate the PWA icon set from static/images/logo.png (speed-test fix 04).

The 2026-08-13 speed test flagged icon-192.png at 89,984 B — 25.4% of total
first-load weight — for something that renders at 192 CSS pixels. The cause was
this script: it resized the source and saved straight to PNG with no
optimisation, and the source art is photographic (tens of thousands of
colours), which is the worst possible case for PNG.

What changed:
  * every icon is also written as WebP, which is what the page actually loads
    (see templates/_install_card.html) — roughly 10x smaller than the PNG,
  * the PNGs are kept, because iOS apple-touch-icon and some PWA installers
    still want them, but they are now quantised and optimised,
  * icon-512 gets the same treatment; it was 485,908 B.

NOTE: static/images/logo.png is placeholder artwork, not a brand mark. A real
logo drawn as vector would let every one of these files be a single SVG of a
few hundred bytes. Until then, re-encoding is the available win.

Run:  python3 generate_icons.py
"""

import os

from PIL import Image

SIZES = [72, 96, 128, 144, 152, 180, 192, 512]
OUTPUT_DIR = "static/icons"
SOURCE = "static/images/logo.png"

# Quality/size knobs. WebP at 82 is visually indistinguishable at icon scale;
# the PNG palette is capped because a 192px icon does not need 30,000 colours.
WEBP_QUALITY = 82
PNG_COLORS = 128


def emit(img, size):
    """Write icon-<size>.webp and icon-<size>.png, return (webp, png) bytes."""
    resized = img.resize((size, size), Image.LANCZOS)

    webp_path = os.path.join(OUTPUT_DIR, "icon-%d.webp" % size)
    resized.save(webp_path, "WEBP", quality=WEBP_QUALITY, method=6)

    png_path = os.path.join(OUTPUT_DIR, "icon-%d.png" % size)
    # Quantise with an alpha-aware palette, then let zlib work hardest.
    quantised = resized.quantize(colors=PNG_COLORS, method=Image.FASTOCTREE)
    quantised.save(png_path, "PNG", optimize=True)

    return os.path.getsize(webp_path), os.path.getsize(png_path)


def main():
    os.makedirs(OUTPUT_DIR, exist_ok=True)
    img = Image.open(SOURCE).convert("RGBA")

    total_webp = total_png = 0
    print("%-6s %11s %11s" % ("size", "webp", "png"))
    for size in SIZES:
        webp_bytes, png_bytes = emit(img, size)
        total_webp += webp_bytes
        total_png += png_bytes
        print("%-6d %9d B %9d B" % (size, webp_bytes, png_bytes))

    print("-" * 30)
    print("webp total %d B / png total %d B" % (total_webp, total_png))
    print("the page loads the webp; PNGs are install-time fallbacks only")


if __name__ == "__main__":
    main()
