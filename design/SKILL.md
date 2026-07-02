---
name: crypto-dashboard
description: Design and build crypto, web3, trading, and on-chain analytics dashboards in a premium terminal-mono aesthetic — monospace type, a near-monochrome dark canvas with one restrained accent, semantic green/red for price direction only, and signature textures (hatch-fills, heatmap grids, pinstripe bars, gauge rings, dotted reference lines). Use this skill whenever the user asks to design, build, restyle, or mock up a crypto dashboard, web3 dashboard, trading dashboard, DeFi dashboard, token analytics, portfolio tracker, or on-chain dashboard, or any interface showing token prices, charts, holdings, or market data, even when phrased casually. Also trigger when the user uploads a crypto/trading screenshot and wants a sharp, data-dense, designer-grade look. Always use this skill for crypto/trading dashboard UI — do NOT design from memory, because the look depends on mono type + held-back color + bespoke textures, which otherwise collapse into a generic glowy-neon AI-crypto template (slop).
---

# Crypto Dashboard

Build crypto and trading dashboards that look like a real product designer made them — closer to a refined Bloomberg terminal than a glowing neon casino. The aesthetic is **terminal-mono**: monospace type, a quiet monochrome dark canvas, one disciplined accent, and a small library of hand-built textures that carry the personality. Restraint is the whole point. Color is earned, not sprayed.

This skill is self-contained. Follow it top to bottom.

---

## Step 1 — Ask before you build

Ask the user these questions in one short batch. For anything they skip or answer "I don't know", apply the **default** and tell them what you picked so they can override. Never block on answers — sensible defaults let you proceed immediately.

1. **Color palette** — pick a preset (see Step 3) or give brand colors. → Default: **Terminal Mono**.
2. **Theme** — dark, light, or both? → Default: **dark** (light variant included for free).
3. **What's the dashboard for** — trading/charts, portfolio tracking, DeFi/staking, NFT, or general analytics? This decides which panels lead. → Default: **trading + portfolio overview**.
4. **Density** — dense (terminal, many panels) or relaxed (fewer, larger cards)? → Default: **dense**.
5. **Tech target** — single HTML file, React + Tailwind, or framework-agnostic markup? → Default: **single self-contained HTML file** with embedded CSS/JS so it runs anywhere.
6. **Real or mock data** — wire to an API, or render realistic placeholder data? → Default: **realistic mock data** (clearly fake numbers, never implied live).

Keep it to one message. Then build. Do not ask follow-ups mid-build unless something is genuinely ambiguous.

---

## Step 2 — Non-negotiables (the anti-slop contract)

These are what separate this from generic AI crypto UI. Hold all of them.

- **Monospace is the identity.** Use a mono typeface for *everything* — headings, labels, body, numbers. This single choice does most of the work. Default: **IBM Plex Mono**. Alternates: JetBrains Mono, Space Mono, Geist Mono. Load via Google Fonts or CDN.
- **Color is held back.** The canvas is near-monochrome. Exactly **one** structural accent. Green/red appear **only** to signal price/value direction (up/down, profit/loss) — never decoratively. If you're reaching for a third hue to make it "pop", stop.
- **Real icons only.** Use a proper line-icon set: **Lucide**, **Phosphor**, **Heroicons**, or **Tabler**. Thin stroke (~1.5px), 16–20px. **Never use emoji** as icons or accents.
- **Texture over gradient glow.** Personality comes from hatching, grids, pinstripes, and segmented rings (Step 6) — not from neon blur, drop-glows, or rainbow gradients. Avoid the glassmorphism-neon cliché entirely.
- **Flat surfaces on a single canvas.** Cards, the search input, and the profile chip sit *directly on `--bg`* and are delineated by their 1px hairline border alone — not by a lighter fill. This near-flat treatment is what makes it read like a terminal rather than a stack of floating panels. Reserve `--surface` / `--surface-2` for the few genuinely inset elements: token-monogram chips, empty heatmap cells, and secondary toggle tracks. Don't tint whole cards a lighter gray.
- **Uniform 4px radius.** `border-radius: 4px` on nearly everything — cards, panels, inputs, buttons, toggles, chips, chart elements. Just enough to soften the corners; no large radii, no pills. Keep it consistent — mixed or heavy rounding reads generic and breaks the look. The two deliberate exceptions: **round token logos / avatars into circles** (a small monogram or avatar coin reads better round), and let tiny texture cells (heatmap squares, swatches) drop to ~1–2px so they stay crisp. Enforce the uniformity with a global `*{border-radius:4px!important}` and override only those exceptions with `!important`.
- **No outer frame.** The app does **not** get its own border or boxed frame, and neither does the top bar — they sit flush on `--bg`. Borders belong to the individual cards only. (This is a change from a bordered "floating app" frame: the borderless canvas with self-contained bordered cards is the intended look.)
- **Thin, quiet structure.** 1px low-contrast borders. Flat surfaces with barely-there elevation. No heavy drop shadows.
- **Tabular numbers.** Enable `font-variant-numeric: tabular-nums` so columns of figures align. This is why mono matters for finance.
- **Micro-animations, always reduced-motion safe** (Step 7).
- **Never fake live data.** Mock numbers must read as illustrative, not as real market quotes.

If you catch yourself producing: a purple→blue gradient hero, glowing card edges, emoji coin icons, a candlestick chart with neon green/red bodies on every candle, or five accent colors — you've drifted into slop. Reset to monochrome + one accent + texture.

---

## Step 3 — Preset color palettes

Each preset is a full token set. Default is **Terminal Mono**. Wire these to CSS custom properties so the theme is swappable. `--up`/`--down` are reserved for price direction; `--accent` is the single structural accent. Note on surfaces: in the default flat treatment (Step 2) the card/input/chip background is `--bg`, not `--surface` — keep `--surface` and `--surface-2` defined but use them only for small inset wells (monogram chips, empty heatmap cells, secondary toggle tracks).

### Terminal Mono (default) — dark
```
--bg:        #0A0A0B   /* app background, near-black */
--surface:   #141417   /* cards / panels */
--surface-2: #1B1C20   /* nested wells, inputs */
--border:    #26272B   /* 1px hairline borders */
--text:      #F4F4F5   /* primary */
--text-dim:  #6B6E76   /* labels, secondary */
--accent:    #225AEB   /* links, active, primary CTA */
--up:        #3FCF8E   /* mint — positive */
--down:      #F4604D   /* coral — negative */
--hatch:     #2E2F34   /* texture line color */
```
Light variant: `--bg:#D9DEDC --surface:#FFFFFF --surface-2:#EEF1F0 --border:#C7CDCB --text:#101212 --text-dim:#565B66` (keep accent/up/down).

### Carbon Amber — dark, CRT terminal warmth
```
--bg:#0B0A08 --surface:#15130F --surface-2:#1D1A14 --border:#2C281F
--text:#F5EFE2 --text-dim:#7A7363 --accent:#E8A33D --up:#7FB069 --down:#D9594C --hatch:#332E22
```

### Midnight Indigo — dark, cool and clinical
```
--bg:#08090F --surface:#111320 --surface-2:#181B2B --border:#262A3D
--text:#EAECF5 --text-dim:#646B86 --accent:#7C6CF6 --up:#46C9A0 --down:#EF5F7A --hatch:#272B3E
```

### Forest Mint — dark, muted green-black
```
--bg:#070B09 --surface:#101613 --surface-2:#161E1A --border:#243029
--text:#EDF3EF --text-dim:#637067 --accent:#2FAE76 --up:#5FD39A --down:#E0664F --hatch:#26332C
```

### Paper Slate — light, editorial
```
--bg:#E7EAE9 --surface:#FFFFFF --surface-2:#F2F4F3 --border:#D2D7D6
--text:#15171A --text-dim:#5C636B --accent:#1F4FD6 --up:#13935E --down:#CE4031 --hatch:#D8DDDC
```

If the user gives a brand color, map it to `--accent`, keep the monochrome bg/surface/border scaffold, and keep semantic up/down. Don't recolor the whole UI in the brand hue.

---

## Step 4 — Typography

- **Family:** mono everywhere (default IBM Plex Mono). Load weights 400/500/600/700.
- **Wordmark / big stat numbers:** 600–700 weight, generous size, tight tracking.
- **Body / data:** 400–500.
- **Labels / captions:** 500, small (11–12px), `--text-dim`, occasionally UPPERCASE with `letter-spacing: 0.06em` for section eyebrows.
- **Numbers:** `font-variant-numeric: tabular-nums` on every numeric element. Right-align numeric table columns.
- Set a comfortable base (14px desktop), line-height ~1.4. Mono runs slightly wide — don't crowd.

---

## Step 5 — Layout & structure

- **App frame:** the dashboard sits flush on the `--bg` canvas with a sensible `max-width` and centered margins — **no outer border, no boxed frame**. The top bar is borderless too. Structure comes from the bordered cards inside, not from a frame around everything. (Don't wrap the app in its own border — that "floating app" framing is explicitly not the look here.)
- **Top bar:** wordmark + mark (a simple geometric glyph, e.g. a hexagon or asterisk — not an emoji) · large search input (background `--bg`, 1px border — flat on the canvas, *not* a lighter fill) with a `/` keyboard-hint chip · center nav links · notification bell · profile chip (background `--bg`, 1px border; avatar + name + truncated wallet `0x4a7B…Cef1` + chevron). The avatar is a plain monogram/figure with **no filled color background** — just the glyph on the canvas.
- **Primary grid:** two columns — **main ~66%** (hero chart + a row or two of analytic panels) and **sidebar ~34%** (portfolio summary, an unlocks/allocation module, an AI-assistant or activity panel stacked).
- **Cards:** background `--bg` (flat on the canvas), 1px `--border`, **4px radius**, ~18–24px padding. Cards are told apart by their border, not by a lighter fill. Header row = title top-left, controls (segmented toggles / icon buttons) top-right. For a panel whose viz should reach the card's bottom edge (e.g. an activity heatmap), make the card a flex column and let the viz grid `flex:1; min-height:0` so it fills the height instead of leaving dead space.
- **Gaps:** 12–16px between cards. Dense by default; each card still breathes internally.
- **Responsive:** collapse to single column under ~1024px; sidebar modules stack below main.

---

## Step 6 — Signature textures (build these, don't skip them)

These hand-built elements are where the "real designer" feeling lives. Render them with inline SVG or CSS — no image assets.

- **Diagonal hatch fill (the signature, used for the "down" direction):** an SVG `<pattern>` of thin diagonal lines, used as a fill alongside solid bars/candles. The key move is pairing **solid for "up" / hatched for "down"** in the same chart — solid `--up` (green) up-bars next to `--down`-stroked diagonal-hatch down-bars. Build a separate hatch pattern per chart whose `stroke` is the relevant color (a `--down`-colored hatch for sells/red candles), and give the hatched shapes a matching 1px colored outline so they read clearly. If you ever hatch over the dark canvas itself (e.g. a gauge segment), brighten the line color (~`#8A8E97`) so it doesn't vanish into the background.
- **Monochrome heatmap grid:** GitHub-contribution style cells at a small (~1–2px) radius. Fill steps from `--surface-2` (empty) → mid gray → `--text` (hot). Use for "transactions" / "activity" panels, with month labels beneath. Let the grid **fill the card to its bottom edge** — make the card a flex column and the grid `flex:1; min-height:0` with `grid-auto-rows:1fr` (bump the row count so stretched cells stay roughly square) rather than leaving blank space below.
- **Pinstripe / barcode distribution bar (the "holders" panel):** a distribution strip built from **dense, uniform-height vertical bars** at a fixed pitch (a barcode, not a descending histogram — every bar is the same height). Make it two-tone by cohort region: brighter bars (~`#c9ccd1`) under the dominant cohort, dimmer (~`#8d9097`) under the others, with **bright 1px vertical divider lines** at the cohort boundaries. Cohort labels + percentages sit above; a uniform barcode reads far cleaner here than variable-height bars.
- **Segmented gauge ring:** a donut built from SVG arcs — one solid segment, one hatched, thin stroke (~10–12px), small gaps between segments, optional radial tick marks around it, large `%` numeral centered, legend beside it with tiny square swatches. Use the brightened hatch color so the hatched arc reads on the dark ring.
- **Dotted reference line:** on the price chart, a horizontal dotted line at the current price with a small inset price tag. On a ratio chart (e.g. Long/Short), put the dotted reference at the pivot value (1.00) in `--down` and split the area fill two-tone — `--up` above the line, `--down` below — via an SVG clipPath at the pivot's y.
- **Candlesticks (colored + hatched by default):** up candles = solid `--up`; **down candles = `--down` diagonal hatch fill with a 1px `--down` outline** (the same striped treatment as red "sell" volume bars — keep them visually consistent). Thin wicks, faint grid and axis ticks in `--text-dim`. This directional solid-vs-hatch coloring — not flat monochrome candles — is the default look. (Plain monochrome candles are fine only if the user explicitly asks.)

Segmented toggle groups (`1D / 7D / 1M / 1Y / All`) come in two treatments — both are 4px-radius, with the **active** item as a 1px outlined box and inactive items as plain `--text-dim` text:
  - **Primary / hero range selector** (the main price chart's): track background `--bg` (flat on the canvas, not a filled pill), and the active box uses a bright `--text` (white) border so the current range pops.
  - **Secondary / inline toggles** (on smaller panels — heatmap, volume, ratio): a subtle filled pill is fine — track `--surface-2`, active item filled `--surface` with a `--border` outline.
  The active outline animates when it moves.

---

## Step 7 — Micro-animations

Tasteful, fast, purposeful. Everything wrapped so it respects motion preferences.

- **Number roll-up:** stat values count from 0 → target on mount (~600ms, ease-out).
- **Chart draw-in:** line/area paths animate via `stroke-dashoffset`; candlesticks fade/scale-up in a quick stagger.
- **Gauge sweep:** ring arcs animate from 0 to value on load.
- **Heatmap stagger:** squares fade in with a small per-cell delay.
- **Segmented toggle:** the active outline slides between items (~180ms).
- **Hover:** card border brightens toward `--text-dim`; a 1–2px lift at most. Tooltips fade in on chart hover. No big shadows, no glow.
- **Timing:** 150–250ms for interactions, ≤600ms for entrances. Ease-out. Never bouncy.

Always include:
```css
@media (prefers-reduced-motion: reduce) {
  *, *::before, *::after {
    animation-duration: 0.01ms !important;
    animation-iteration-count: 1 !important;
    transition-duration: 0.01ms !important;
  }
}
```

---

## Step 8 — Icons

- Use **Lucide** (default), Phosphor, Heroicons, or Tabler. In a single HTML file, pull Lucide from CDN and call `lucide.createIcons()`.
- Stroke ~1.5px, size 16–20px, color `--text-dim` (or `--text` when active). Keep icons monochrome.
- Common set: search, bell, candlestick/line-chart toggles, sliders (indicators), arrow-up/down (price direction), download, maximize/fullscreen, chevron-down, undo/redo, calendar, wallet, send, paperclip, **bot** (for an AI-assistant panel — use a robot icon, not a sparkle).
- **No emoji. Ever.** Not in nav, not as coin logos, not as status dots. For token logos use a simple lettered/geometric monogram chip if you don't have real logo assets — and **make that chip circular** (it's one of the few round elements; the rest of the UI stays 4px).

---

## Step 9 — Suggested panels (pick per the dashboard's purpose)

Lead with the panels that match the user's stated use case; include 4–7 total so it feels complete but not bloated.

- **Hero price chart** — candlesticks + toolbar (timeframe toggles, chart-type toggles, indicators, price/market-cap toggle, fullscreen).
- **Portfolio summary** — Today / Month / Year columns with big mono numbers and colored % change + direction arrow (green up / red down). Below them an **allocation heatmap**: a grid of small monochrome squares split into **discrete brightness bands**, one band per holding, each band's column-width proportional to that holding's weight (brightest = largest allocation → darkest = smallest). Distinct stepped bands, **not a smooth gradient** — and a legend of token + % beneath.
- **Unlocks / vesting** — the segmented gauge ring + a labeled breakdown list.
- **Activity heatmap** — the monochrome grid, filled to the bottom of its card (see Step 6).
- **Holders / distribution** — the uniform-height barcode bar (Step 6), two-tone by cohort with bright dividers and cohort percentages.
- **Volume** — bar chart mixing solid and hatched bars: **buys = solid `--up`, sells = `--down` diagonal hatch** (same striped red as the down candles). Summary stats (txns, vol, fees, net buy — net buy colored by sign).
- **Long/Short or sentiment** — a filled area chart split two-tone at the 1.00 pivot (`--up` above, `--down` below), with a dotted `--down` reference line at 1.00 and a hover tooltip (green dot = Long, red dot = Long/Short).
- **AI assistant / activity feed** — chat-style panel headed by a **robot (bot)** icon. User bubble right (darker, on-canvas). The assistant's reply bubble is a **light / inverted color** (a soft light mint like `#cdded9` with dark `#10201d` text) — a deliberate single bright element that lifts the panel against the dark canvas. Bold inline figures; input row with attach + send icons.

---

## Step 10 — Output & quality bar

- Default deliverable: **one self-contained `.html` file** (embedded CSS + JS, fonts + Lucide via CDN) that opens and runs immediately. Offer React/Tailwind only if the user asked.
- Use CSS custom properties for the chosen palette so theme-switching is trivial.
- Charts: hand-build with SVG/Canvas, or a lightweight lib (uPlot, Chart.js) if the user is fine with a dependency — but keep the mono/monochrome/texture styling on top.
- Make mock data realistic but obviously illustrative.

**Before you finish, check:**
- [ ] Mono font on everything, tabular numerals on all figures.
- [ ] Monochrome canvas + exactly one accent; green/red only for direction — but applied consistently everywhere direction appears (candles, volume bars, ratio area, % changes).
- [ ] Cards / search / profile chip sit flat on `--bg`, told apart by 1px borders — no lighter-gray card fills.
- [ ] **No outer app frame or top-bar border**; only individual cards have borders.
- [ ] Down direction uses the diagonal-hatch treatment (down candles + sell bars), up is solid `--up`.
- [ ] Real line icons, zero emoji; AI panel uses a robot icon; token logo / avatar are circular, everything else 4px.
- [ ] Signature textures present: hatch candles/bars, height-filling heatmap, uniform barcode holders bar, gauge ring.
- [ ] Portfolio allocation reads as discrete brightness bands, not a gradient.
- [ ] 1px hairline borders, **uniform 4px radius** (circular logo/avatar the only exception).
- [ ] Micro-animations present and `prefers-reduced-motion` honored.
- [ ] Nothing reads as a glowing-neon AI crypto template.
- [ ] Responsive collapse to one column on narrow screens.
