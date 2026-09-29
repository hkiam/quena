#!/usr/bin/env python3
"""Turn the Piper artwork (rounded square on black) into a 1024x1024 source
icon with transparent corners, then run `tauri icon` for all platforms.

usage: tools/icon/make_icon.py path/to/artwork.png [--threshold N] [--radius F]

  --threshold  brightness (0-255) above which a pixel counts as artwork (default 24)
  --radius     corner radius of the mask as a fraction of the side (default 0.225);
               use a value >= the artwork's own corner radius so no background shows
"""
import subprocess
import sys
from pathlib import Path

from PIL import Image, ImageChops, ImageDraw, ImageFilter

ROOT = Path(__file__).resolve().parents[2]
OUT = ROOT / "app/src-tauri/icons"


def main(src: str, threshold: int = 24, radius: float = 0.225) -> None:
    im = Image.open(src).convert("RGBA")
    # Bounding box of the non-black artwork.
    gray = im.convert("L").point(lambda v: 255 if v > threshold else 0)
    bbox = gray.getbbox() or (0, 0, im.width, im.height)
    art = im.crop(bbox)
    side = max(art.size)
    sq = Image.new("RGBA", (side, side), (0, 0, 0, 0))
    sq.paste(art, ((side - art.width) // 2, (side - art.height) // 2))
    # Rounded-square mask (continuous-corner approximation, ~22% radius as on macOS).
    scale = 4
    big = side * scale
    mask = Image.new("L", (big, big), 0)
    ImageDraw.Draw(mask).rounded_rectangle((0, 0, big - 1, big - 1), radius=int(big * radius), fill=255)
    mask = mask.resize((side, side), Image.LANCZOS)
    alpha = ImageChops.multiply(sq.getchannel("A"), mask)
    sq.putalpha(alpha)
    # macOS grid: artwork body 824/1024 centred; other platforms use the full square.
    body = sq.resize((824, 824), Image.LANCZOS)
    mac = Image.new("RGBA", (1024, 1024), (0, 0, 0, 0))
    shadow = Image.new("RGBA", (1024, 1024), (0, 0, 0, 0))
    sh = Image.new("RGBA", (824, 824), (0, 0, 0, 110))
    sh.putalpha(ImageChops.multiply(body.getchannel("A"), Image.new("L", (824, 824), 110)))
    shadow.paste(sh, (100, 112), sh)
    shadow = shadow.filter(ImageFilter.GaussianBlur(14))
    mac.alpha_composite(shadow)
    mac.alpha_composite(body, (100, 100))
    full = sq.resize((1024, 1024), Image.LANCZOS)
    OUT.mkdir(parents=True, exist_ok=True)
    full.save(OUT / "source.png")
    mac.save(OUT / "source-macos.png")
    ui = ROOT / "app/ui"
    tauri = ui / "node_modules/.bin/tauri"
    # All platforms from the full-bleed square, then macOS .icns from the padded variant.
    subprocess.run([str(tauri), "icon", str(OUT / "source.png"), "-o", str(OUT)], check=True, cwd=ui)
    tmp = OUT / "_mac"
    subprocess.run([str(tauri), "icon", str(OUT / "source-macos.png"), "-o", str(tmp)], check=True, cwd=ui)
    (tmp / "icon.icns").replace(OUT / "icon.icns")
    for p in tmp.rglob("*"):
        if p.is_file():
            p.unlink()
    for p in sorted(tmp.rglob("*"), reverse=True):
        p.rmdir()
    tmp.rmdir()
    # Favicon for the web UI.
    full.resize((64, 64), Image.LANCZOS).save(ui / "public/favicon.png") if (ui / "public").exists() else None
    print("icons written to", OUT)


if __name__ == "__main__":
    import argparse

    ap = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument("artwork")
    ap.add_argument("--threshold", type=int, default=24)
    ap.add_argument("--radius", type=float, default=0.225)
    a = ap.parse_args()
    main(a.artwork, a.threshold, a.radius)
