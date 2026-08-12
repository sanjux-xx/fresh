from PIL import Image
import os

SIZES = [72, 96, 128, 144, 152, 180, 192, 512]
OUTPUT_DIR = "static/icons"

os.makedirs(OUTPUT_DIR, exist_ok=True)

img = Image.open("static/images/logo.png").convert("RGBA")

for size in SIZES:
    resized = img.resize((size, size), Image.LANCZOS)
    resized.save(os.path.join(OUTPUT_DIR, f"icon-{size}.png"))
    print(f"✅ icon-{size}.png")

print("Done!")