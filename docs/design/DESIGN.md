# Design Guidelines — Crypto Dashboard (Terminal-Mono)

## Visual Style
- **Aesthetic**: Near-monochrome dark crypto/trading dashboard, monospace throughout, data-dense. Reads like a refined Bloomberg terminal — deliberately NOT glowy-neon crypto.
- **Mood**: Sharp, technical, precise, restrained, designer-grade.
- **Inspiration**: Bloomberg terminal × IBM Plex design language × "Numora"-style on-chain analytics.

## Color Palette (default: Terminal Mono, dark)
- **Primary / Accent**: #225AEB — links, active states, primary CTA. The ONE structural accent; used sparingly.
- **Background**: #0A0A0B (near-black) — also the fill for cards, search input, and profile chip (flat canvas).
- **Surface / Card**: #141417 — reserved for small inset wells ONLY (monogram chips, empty heatmap cells, secondary toggle tracks), never whole cards.
- **Surface-2**: #1B1C20 — nested wells / inputs.
- **Text Primary**: #F4F4F5
- **Text Secondary**: #6B6E76
- **Border**: #26272B — 1px hairlines; the only thing separating cards.
- **Success / Up**: #3FCF8E (mint) — positive price direction only.
- **Error / Down**: #F4604D (coral) — negative price direction only.
- **Hatch (texture lines)**: #2E2F34 — brighten to ~#8A8E97 when hatching over the dark canvas.
- **Rule**: monochrome base + one accent; green/red ONLY for direction, never decorative.
- **Presets**: Carbon Amber, Midnight Indigo, Forest Mint (dark), Paper Slate (light), plus a Terminal Mono light variant.

## Typography
- **Primary Font**: Monospace — IBM Plex Mono (alts: JetBrains Mono, Space Mono, Geist Mono). Mono on EVERYTHING.
- **Headings / big numbers**: 600–700, generous size, tight tracking.
- **Body / data**: 400–500.
- **Labels / Captions**: 500, 11–12px, muted; occasionally UPPERCASE with 0.06em tracking for section eyebrows.
- **Numbers**: `font-variant-numeric: tabular-nums` on every figure; right-align numeric columns.
- Base ~14px desktop, line-height ~1.4. Mono runs wide — don't crowd.

## Spacing & Layout
- **Overall feel**: Dense but breathing — terminal density, each card padded internally.
- **App frame**: Flush on the bg canvas with a max-width and centered margins. NO outer border or boxed frame; top bar is borderless too.
- **Grid**: Two columns — main ~66% (hero chart + analytic panel rows), sidebar ~34% (portfolio, unlocks/allocation, AI assistant stacked).
- **Card padding**: ~18–24px. **Gaps**: 12–16px between cards.
- **Mobile**: Collapse to single column under ~1024px; sidebar modules stack below main.

## Borders & Radius
- **Border radius**: Uniform 4px on nearly everything (cards, inputs, buttons, toggles, chips, chart elements). Enforce with a global `*{border-radius:4px}`.
- **Exceptions**: Token logos / avatars are CIRCULAR; tiny texture cells (heatmap squares, swatches) drop to ~1–2px.
- **Borders**: 1px solid #26272B. Cards are told apart by their border alone — no lighter fill.

## Shadows & Elevation
- Flat. No heavy shadows, no glow. Hover = border brightens toward text-dim + a 1–2px lift at most.

## Buttons & Toggles
- **Primary CTA**: Accent- or text-colored, 4px radius, mono label.
- **Segmented range toggles** (1D / 7D / 1M / 1Y / All): active = 1px outlined box, inactive = plain muted text.
  - Hero range selector: track flat on bg, active box uses a bright white border.
  - Inline panel toggles: subtle filled — track `--surface-2`, active item filled `--surface` with a border.

## Icons
- Real line icons only — Lucide (default), Phosphor, Heroicons, Tabler. ~1.5px stroke, 16–20px, monochrome.
- AI-assistant panel uses a **robot (bot)** icon — not a sparkle.
- NO emoji anywhere (not nav, coin logos, or status dots). Token logo = circular lettered/geometric monogram chip.

## Signature Textures & Data-Viz (the design's DNA — don't skip)
- **Diagonal hatch fill**: The signature move — pair solid (up) vs hatched (down) in the same chart. Hatch stroke = the relevant color (down/red), with a matching 1px outline.
- **Candlesticks**: up = solid `--up`; down = `--down` diagonal hatch + 1px `--down` outline. Directional solid/hatch by default, not flat monochrome.
- **Volume bars**: buys = solid `--up`, sells = `--down` hatch (same striped red as down candles).
- **Heatmap grid**: GitHub-style monochrome cells (~1–2px radius), brightness steps empty→hot; fill the card to its bottom edge (flex column, grid `flex:1; min-height:0`).
- **Holders / distribution**: Uniform-height "barcode" bar (every bar the same height), two-tone by cohort with bright 1px dividers — NOT a descending histogram.
- **Segmented gauge ring**: SVG arcs, one solid + one hatched, thin 10–12px stroke, small gaps, optional radial ticks, large % centered, legend with square swatches.
- **Long/Short ratio**: Two-tone area split at the 1.00 pivot (`--up` above / `--down` below) via clipPath, with a dotted `--down` reference line at the pivot.
- **Allocation**: Discrete brightness BANDS — one per holding, width ∝ weight, brightest = largest. Stepped, NOT a smooth gradient. Legend of token + % beneath.
- **Price chart**: Dotted horizontal reference line at current price with a small inset price tag; faint grid + axis ticks in text-dim.

## Components Spotted
- **Top bar**: Wordmark + geometric mark (hexagon/asterisk), large flat search input with a "/" hint chip, center nav links, notification bell, profile chip (flat, monogram avatar + name + truncated wallet `0x4a7B…Cef1` + chevron).
- **Cards**: bg-colored, 1px border, 4px radius; title top-left + controls top-right.
- **Portfolio**: Today / Month / Year columns, big mono numbers, colored % change + direction arrow.
- **AI assistant**: Chat panel headed by a robot icon. User bubble right (dark, on-canvas); assistant reply bubble light/inverted (soft mint ~#cdded9 with dark ~#10201d text) as a single deliberate bright element; input row with attach + send icons.

## Micro-Animations
- Number roll-up (count 0→target ~600ms), chart draw-in (stroke-dashoffset), candle stagger, gauge sweep, heatmap stagger fade, toggle active-outline slide (~180ms), tooltip fade. 150–250ms interactions, ≤600ms entrances, ease-out, never bouncy. Always honor `prefers-reduced-motion`.

## Overall Replication Notes
- Mono font on everything + tabular numerals — this single move carries the identity.
- Monochrome canvas + exactly ONE accent; green/red only for direction, applied consistently (candles, volume, ratio, % changes).
- Cards sit flat on bg, separated by 1px borders — never a lighter card fill; no outer app frame or top-bar border.
- Personality comes from hand-built textures (hatch, barcode, heatmap, gauge) — not gradients or glow.
- Down direction always uses diagonal hatch; up is solid.
- Everything is 4px except circular logos/avatars.
- Avoid slop: no neon gradients, glassmorphism, glowing edges, emoji icons, or 5-color palettes.
