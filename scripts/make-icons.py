#!/usr/bin/env python3
"""
Generates the ShadowShield icon set.

Mark: a lighthouse inside a shield. The lighthouse is the product's actual
job — it stands on the hazard and warns you off before you run aground —
which is a truer metaphor for phishing protection than a generic padlock,
and it belongs to the maritime world without borrowing the raider's flag.

Art is simplified per size rather than scaled blindly. At 16px the tower
banding and beam rays turn to mush, so that size drops to the silhouette
plus the lantern light. Chrome uses each size in a different place; they
do not have to be the same drawing.
"""

from PIL import Image, ImageDraw

SS = 8  # supersample factor; downsampled with LANCZOS for clean edges

# Palette (must stay in step with the CSS custom properties in pages/)
ABYSS = (10, 20, 32)
HULL = (18, 32, 47)
BRASS = (201, 151, 63)
BRASS_HI = (232, 190, 112)
CHART = (232, 238, 244)
BEAM = (201, 151, 63)


def shield_polygon(w, h, inset):
    """Heater shield: flat shoulders, sides sweeping to a point at the keel."""
    x0, x1 = inset, w - inset
    y0, y1 = inset, h - inset
    shoulder = y0 + (y1 - y0) * 0.26
    pts = [(x0, y0), (x1, y0), (x1, shoulder)]
    # Right flank sweeping in to the point
    steps = 48
    for i in range(steps + 1):
        t = i / steps
        # ease-in curve: stays wide, then turns hard toward the keel
        x = x1 - (x1 - w / 2) * (t ** 2.4)
        y = shoulder + (y1 - shoulder) * t
        pts.append((x, y))
    # Left flank, mirrored
    for i in range(steps, -1, -1):
        t = i / steps
        x = x0 + (w / 2 - x0) * (t ** 2.4)
        y = shoulder + (y1 - shoulder) * t
        pts.append((x, y))
    pts.append((x0, shoulder))
    return pts


def draw_icon(px, detail="full"):
    w = h = px * SS
    img = Image.new("RGBA", (w, h), (0, 0, 0, 0))
    d = ImageDraw.Draw(img)

    inset = w * 0.045
    shield = shield_polygon(w, h, inset)

    # Shield body, with a brass rim. The rim is what keeps the silhouette
    # legible against both light and dark browser themes.
    rim = max(2, int(w * 0.032))
    d.polygon(shield, fill=HULL, outline=BRASS)
    for k in range(rim):
        d.line(shield + [shield[0]], fill=BRASS, width=rim - k, joint="curve")
    inner = shield_polygon(w, h, inset + rim * 1.1)
    d.polygon(inner, fill=ABYSS)

    cx = w / 2

    if detail == "full":
        # Beam rays first, so the tower sits on top of them.
        top_y = h * 0.30
        for direction in (-1, 1):
            for spread, alpha in ((0.13, 165), (0.26, 105), (0.40, 55)):
                layer = Image.new("RGBA", (w, h), (0, 0, 0, 0))
                ld = ImageDraw.Draw(layer)
                ld.polygon(
                    [
                        (cx, top_y),
                        (cx + direction * w * 0.62, top_y - h * spread),
                        (cx + direction * w * 0.62, top_y + h * spread * 0.55),
                    ],
                    fill=BEAM + (alpha,),
                )
                img.alpha_composite(layer)
        # Re-clip the beams to the shield interior
        mask = Image.new("L", (w, h), 0)
        ImageDraw.Draw(mask).polygon(inner, fill=255)
        img.putalpha(Image.composite(img.getchannel("A"), Image.new("L", (w, h), 0), mask))

    d = ImageDraw.Draw(img)

    # Tower: tapered, standing on a base. Proportions differ per detail level
    # so the shape stays readable when it is only a few pixels wide.
    if detail == "full":
        top_w, bot_w = w * 0.105, w * 0.185
        t_top, t_bot = h * 0.345, h * 0.735
    else:
        top_w, bot_w = w * 0.155, w * 0.245
        t_top, t_bot = h * 0.375, h * 0.700

    d.polygon(
        [(cx - top_w, t_top), (cx + top_w, t_top),
         (cx + bot_w, t_bot), (cx - bot_w, t_bot)],
        fill=CHART,
    )

    if detail == "full":
        # Two bands. Reads as a lighthouse rather than a pillar.
        for frac in (0.42, 0.68):
            y = t_top + (t_bot - t_top) * frac
            band_h = (t_bot - t_top) * 0.11
            wl = top_w + (bot_w - top_w) * frac
            wr = top_w + (bot_w - top_w) * (frac + 0.11)
            d.polygon(
                [(cx - wl, y), (cx + wl, y), (cx + wr, y + band_h), (cx - wr, y + band_h)],
                fill=BRASS,
            )

    # Lantern room — the light itself. This is the one element every size keeps.
    lr = w * (0.108 if detail == "full" else 0.165)
    ly = t_top - lr * 0.55
    d.ellipse([cx - lr, ly - lr, cx + lr, ly + lr], fill=BRASS_HI)
    if detail == "full":
        d.ellipse([cx - lr * 0.45, ly - lr * 0.45, cx + lr * 0.45, ly + lr * 0.45], fill=CHART)
        # Gallery rail under the lantern
        d.rectangle([cx - top_w * 1.5, t_top - h * 0.012,
                     cx + top_w * 1.5, t_top + h * 0.016], fill=BRASS)

    # Base plinth
    bw = bot_w * (1.35 if detail == "full" else 1.25)
    d.rectangle([cx - bw, t_bot, cx + bw, t_bot + h * 0.035], fill=BRASS)

    return img.resize((px, px), Image.LANCZOS)


if __name__ == "__main__":
    import os
    out = os.path.join(os.path.dirname(__file__), "..", "icons")
    os.makedirs(out, exist_ok=True)
    for px, detail in ((128, "full"), (48, "full"), (16, "simple")):
        p = os.path.join(out, f"icon{px}.png")
        draw_icon(px, detail).save(p)
        print(f"wrote icons/icon{px}.png ({detail})")
    # Oversized master for the Web Store listing / README
    draw_icon(512, "full").save(os.path.join(out, "icon512.png"))
    print("wrote icons/icon512.png (full)")
