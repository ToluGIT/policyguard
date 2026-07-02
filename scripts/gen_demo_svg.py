#!/usr/bin/env python3
"""Render a PolicyGuard demo capture into a static terminal-style SVG.

This is the dependency-free fallback for generating docs/assets/demo.svg when
svg-term/asciinema are not installed. It takes the *real* output of
`scripts/demo.sh --asset` on stdin and lays it out as a terminal window, so the
committed asset is a faithful (if static) capture of an actual scan — not a mockup.

Usage:
    ./scripts/demo.sh --asset | python3 scripts/gen_demo_svg.py > docs/assets/demo.svg
"""
import html
import math
import sys

# Terminal palette (a muted dark theme close to common terminal defaults).
BG = "#1d1f21"
HEADER_BG = "#2b2d31"
FG = "#c5c8c6"
GREEN = "#b5bd68"   # prompt / command
RED = "#cc6666"     # CRITICAL
ORANGE = "#de935f"  # HIGH
YELLOW = "#f0c674"  # MEDIUM / section headers
GREY = "#969896"    # comments / dim
CYAN = "#8abeb7"    # exit-code line

FONT = "Menlo, Consolas, 'DejaVu Sans Mono', monospace"
FONT_SIZE = 13
LINE_H = 18
PAD_X = 16
PAD_TOP = 44   # leaves room for the title bar + traffic-light dots
PAD_BOT = 14
CHAR_W = 7.8   # approx advance width at FONT_SIZE for the monospace stack


def color_for(line: str) -> str:
    s = line.strip()
    if line.startswith("$ "):
        return GREEN
    if s.startswith("#") or "deterministic demo capture" in line or s.startswith("..."):
        return GREY
    if s.startswith("[CRITICAL]"):
        return RED
    if s.startswith("[HIGH]"):
        return ORANGE
    if s.startswith("[MEDIUM]") or s.startswith("[LOW]"):
        return YELLOW
    if s in ("SUMMARY", "VIOLATIONS") or s.startswith("PolicyGuard Security Report"):
        return YELLOW
    if s.startswith("CRITICAL:"):
        return RED
    return FG


def main() -> None:
    lines = [ln.rstrip("\n") for ln in sys.stdin.readlines()]
    # Trim trailing blank lines.
    while lines and lines[-1].strip() == "":
        lines.pop()

    max_len = max((len(ln) for ln in lines), default=80)
    # ceil (not truncate) so the last glyph can never overflow the viewBox if
    # the rendered font's advance width edges above CHAR_W.
    width = math.ceil(PAD_X * 2 + max_len * CHAR_W)
    width = max(width, 760)
    height = math.ceil(PAD_TOP + len(lines) * LINE_H + PAD_BOT)

    out = []
    out.append(
        f'<svg xmlns="http://www.w3.org/2000/svg" width="{width}" height="{height}" '
        f'viewBox="0 0 {width} {height}" font-family="{FONT}" font-size="{FONT_SIZE}">'
    )
    out.append(f'<rect width="{width}" height="{height}" rx="8" fill="{BG}"/>')
    out.append(f'<rect width="{width}" height="28" rx="8" fill="{HEADER_BG}"/>')
    out.append(f'<rect y="20" width="{width}" height="8" fill="{HEADER_BG}"/>')
    # Traffic-light dots.
    for i, c in enumerate(("#ff5f56", "#ffbd2e", "#27c93f")):
        out.append(f'<circle cx="{18 + i*18}" cy="14" r="6" fill="{c}"/>')
    out.append(
        f'<text x="{width/2}" y="18" fill="{GREY}" text-anchor="middle" '
        f'font-size="12">policyguard — demo</text>'
    )

    y = PAD_TOP
    for ln in lines:
        color = color_for(ln)
        text = html.escape(ln) if ln else " "
        out.append(
            f'<text xml:space="preserve" x="{PAD_X}" y="{y}" fill="{color}">{text}</text>'
        )
        y += LINE_H

    out.append("</svg>")
    sys.stdout.write("\n".join(out) + "\n")


if __name__ == "__main__":
    main()
