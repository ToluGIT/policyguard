# Demo assets

`demo.svg` is the terminal capture embedded at the top of the project README. It
is a **static** render of the *real* output of a scan — not a mockup and not a
hand-edited image.

## How it is generated

The asset is produced from `scripts/demo.sh`, which runs an actual scan against
`examples/demo/main.tf`:

```bash
# from the repo root
./scripts/demo.sh --asset-short | python3 scripts/gen_demo_svg.py > docs/assets/demo.svg
```

- `scripts/demo.sh --asset-short` runs the scan and emits a **deterministic**
  top-fold capture: the "Generated:" timestamp is pinned, paths are
  repo-relative, and the output is trimmed after the two CRITICAL findings with
  an honest `... 2 more findings` line so the asset stays README-sized. Use
  `--asset` for the full, untrimmed capture.
- `scripts/gen_demo_svg.py` lays that text out as a terminal-style SVG
  (dependency-free; standard-library Python only).

Because the SVG is derived from a real scan, regenerating it after a change to
the demo fixture or the human reporter will surface any drift in a diff.

## Animated alternative (optional)

A static SVG is intentionally low-friction (renders on GitHub, no JS, tiny, and
diffable). If you want an animated cast instead, record one with
[asciinema](https://asciinema.org/) and render it with
[`agg`](https://github.com/asciinema/agg) or
[`svg-term-cli`](https://github.com/marionebl/svg-term-cli):

```bash
asciinema rec demo.cast -c './scripts/demo.sh'
svg-term --in demo.cast --out docs/assets/demo.svg --window
```

Keep whichever asset the README points at faithful to real tool output.
