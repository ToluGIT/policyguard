# PolicyGuard — Brand assets (Terminal Shield)

The GUI logomark for **PolicyGuard**, the Security Policy Scanner for Infrastructure as Code.
A shield (guard) wrapping a `>_` terminal prompt — security + CLI heritage in one mark.
Monochrome by default; the single brand accent is **lime `#C2F24A`**, used for the prompt.

This folder is self-contained and ready to drop into a repo. Hand the whole folder to Claude Code.

---

## Files

```
policyguard-brand/
├─ README.md                     ← this file
├─ tokens.css                    ← color + font custom properties for the whole product
├─ manifest.webmanifest          ← PWA icon manifest
├─ svg/
│  ├─ mark.svg                   ← PRIMARY. shield = currentColor, prompt = lime (themeable)
│  ├─ mark-mono.svg              ← single-color (everything currentColor)
│  ├─ mark-on-dark.svg           ← baked light shield + lime prompt (transparent bg)
│  ├─ mark-on-light.svg          ← baked near-black shield + darkened lime (transparent bg)
│  ├─ favicon.svg                ← dark rounded tile, heavier prompt for small sizes
│  ├─ app-icon.svg               ← 512 dark rounded square (PWA / store icon)
│  └─ lockup-horizontal.svg      ← mark + "PolicyGuard" wordmark
├─ png/
│  ├─ favicon-16/32/48/64.png    ← tile favicons
│  ├─ apple-touch-icon-180.png
│  ├─ app-icon-192/512.png       ← PWA icons
│  ├─ mark-on-dark-128/256.png   ← transparent mark for dark UIs
│  └─ mark-on-light-256.png      ← transparent mark for light UIs
├─ react/
│  └─ PolicyGuardMark.tsx        ← <PolicyGuardMark/> + <PolicyGuardLockup/>
└─ snippets/
   └─ usage.html                 ← inline-SVG, <img>, and favicon <link> examples
```

---

## Which file do I use?

| Context | Use |
|---|---|
| React / component code | `react/PolicyGuardMark.tsx` |
| Theming the shield to match text color | `svg/mark.svg` (inline) |
| Quick `<img>` on a dark UI | `svg/mark-on-dark.svg` |
| Quick `<img>` on a light UI | `svg/mark-on-light.svg` |
| Browser tab | `svg/favicon.svg` + `png/favicon-*.png` |
| Home-screen / PWA | `png/app-icon-*.png`, `manifest.webmanifest` |
| Header / marketing lockup | `svg/lockup-horizontal.svg` |

> **Why two color models?** `mark.svg` / `mark-mono.svg` use `currentColor` so the shield follows your
> CSS `color` — ideal for nav rails where the active item turns lime. The `-on-dark` / `-on-light`
> files bake the colors in for plain `<img>` use where there's no CSS to inherit.

---

## Color & type

```
bg        #0A0A0B      text       #F4F4F5      accent (lime)  #C2F24A
surface   #141417      text-dim   #6B6E76      accent/light   #5C8A00
border    #26272B
severity:  critical #F4604D · high #E8853D · medium #D8B23D · low #5B8FB0 · pass #3FCF8E
font:      IBM Plex Mono (400 / 500 / 600 / 700)
```

Full token set in `tokens.css`. Load the font:
```html
<link href="https://fonts.googleapis.com/css2?family=IBM+Plex+Mono:wght@400;500;600;700&display=swap" rel="stylesheet">
```

---

## Usage rules

- **Clear space:** keep at least the height of the prompt's `_` around the mark.
- **Minimum size:** 16px for the tile `favicon.svg`; 20px for the transparent strokes-only marks.
- **Accent discipline:** lime is for the prompt, primary actions, and the active nav item — nothing decorative. Severity reds/oranges are semantic only.
- **Don't:** recolor the shield into a brand hue, add gradients/glows, fill the shield solid, or stretch the aspect ratio (mark is 100×104).
- **App icon** always sits on the `#0A0A0B` rounded tile; the bare mark is for in-UI use.

---

## React example

```tsx
import { PolicyGuardMark, PolicyGuardLockup } from "./react/PolicyGuardMark";

<PolicyGuardMark size={28} />                       // shield follows text color
<div style={{ color: "#C2F24A" }}>
  <PolicyGuardMark size={28} mono />                // active nav: whole mark lime
</div>
<PolicyGuardLockup height={28} />                   // mark + wordmark
```

## HTML `<head>` example

```html
<link rel="icon" type="image/svg+xml" href="/policyguard-brand/svg/favicon.svg" />
<link rel="icon" type="image/png" sizes="32x32" href="/policyguard-brand/png/favicon-32.png" />
<link rel="apple-touch-icon" sizes="180x180" href="/policyguard-brand/png/apple-touch-icon-180.png" />
<link rel="manifest" href="/policyguard-brand/manifest.webmanifest" />
```

---

*Need a `.ico` (multi-res), animated splash, or the wordmark converted to outlines? Ask and I'll add them.*
