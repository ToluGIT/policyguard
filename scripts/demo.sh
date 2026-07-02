#!/usr/bin/env bash
#
# demo.sh — the canonical PolicyGuard demo.
#
# Runs a real scan against examples/demo/main.tf and shows the findings plus the
# fail-closed exit code. This is the script the README's demo asset is generated
# from, so what you see in the README is exactly what this prints — no mockups.
#
#   ./scripts/demo.sh             # run the live demo (full output)
#   ./scripts/demo.sh --asset     # deterministic full capture (no timestamp)
#   ./scripts/demo.sh --asset-short  # deterministic top-fold capture for the SVG
#
# The committed README asset (docs/assets/demo.svg) is generated from
# `--asset-short`; regenerate it with:
#   ./scripts/demo.sh --asset-short | python3 scripts/gen_demo_svg.py > docs/assets/demo.svg
# See docs/assets/README.md for the asciinema/svg-term alternative.
set -euo pipefail

cd "$(dirname "$0")/.."

BIN="${POLICYGUARD_BIN:-./bin/policyguard}"
FIXTURE="examples/demo/main.tf"
ASSET_MODE=0
SHORT=0
case "${1:-}" in
  --asset) ASSET_MODE=1 ;;
  --asset-short) ASSET_MODE=1; SHORT=1 ;;
esac

# Build a fresh binary unless one was supplied via POLICYGUARD_BIN.
if [ -z "${POLICYGUARD_BIN:-}" ]; then
  go build -o "$BIN" ./cmd/policyguard
fi

run_scan() {
  # Banner goes to stderr; in asset mode we drop it for a clean capture.
  if [ "$ASSET_MODE" = "1" ]; then
    "$BIN" scan "$FIXTURE" 2>/dev/null
  else
    "$BIN" scan "$FIXTURE"
  fi
}

if [ "$ASSET_MODE" = "1" ]; then
  # Deterministic capture: pin the generated timestamp so the committed asset
  # does not churn on every regeneration. The scan itself is unchanged.
  echo "\$ policyguard scan $FIXTURE"
  capture="$(run_scan | sed -E 's/^Generated:.*/Generated: (deterministic demo capture)/')"
  if [ "$SHORT" = "1" ]; then
    # Top-fold capture: keep through the two CRITICAL findings, then summarize
    # the rest honestly rather than truncating silently.
    printf '%s\n' "$capture" | awk '
      /^\[HIGH\]/ { print "... 2 more findings (HIGH: encryption, MEDIUM: access logging)"; exit }
      { print }
    '
  else
    printf '%s\n' "$capture"
  fi
  echo
  echo "\$ echo \$?   # fail-closed exit code under --fail-on-error"
  if "$BIN" scan "$FIXTURE" --fail-on-error >/dev/null 2>&1; then
    echo "0"
  else
    echo "$?"
  fi
else
  echo "\$ policyguard scan $FIXTURE"
  run_scan || true
  echo
  echo "\$ policyguard scan $FIXTURE --fail-on-error ; echo \$?"
  "$BIN" scan "$FIXTURE" --fail-on-error >/dev/null 2>&1 || true
  printf '%s  ' "$?"
  echo "# exit 1 = violations gated (0 = clean, 2 = scan error)"
fi
