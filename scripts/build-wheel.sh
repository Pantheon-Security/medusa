#!/usr/bin/env bash
#
# Build a LEAK-FREE MEDUSA wheel.
#
# The paid-tier files (licensing.py, api/, runtime rules) live in the dev tree
# for convenience but must NEVER ship in the public wheel (CLAUDE.md hard rule).
# .gitignore blocks *commits*, NOT the wheel build — `python -m build` packages
# straight from the working tree. setuptools can exclude whole *packages*
# (medusa.api, medusa.rules.runtime) via pyproject, but it cannot exclude a
# single *module* like medusa/core/licensing.py, which is why it has silently
# leaked into prior wheels.
#
# This script stashes the paid-tier (and non-shipping) paths out of the tree,
# builds, restores them, and then HARD-GATES the resulting wheel: if any paid
# or bloat path is present, it deletes the wheel and exits non-zero.
#
# Usage:  scripts/build-wheel.sh
set -euo pipefail
cd "$(dirname "$0")/.."

# Paths that must not appear in the wheel.
PAID=( "medusa/core/licensing.py" "medusa/api" "medusa/rules/runtime" "medusa-vscode" )

STASH="$(mktemp -d "${TMPDIR:-/tmp}/medusa-build-stash.XXXXXX")"
restore() {
  for p in "${PAID[@]}"; do
    b="$(basename "$p")"; d="$(dirname "$p")"
    [ -e "$STASH/$b" ] && mv "$STASH/$b" "$d/" || true
  done
  rm -rf "$STASH" 2>/dev/null || true
}
trap restore EXIT

echo "==> Stashing paid-tier / non-shipping paths out of the build tree"
for p in "${PAID[@]}"; do
  [ -e "$p" ] && mv "$p" "$STASH/" && echo "    stashed $p" || true
done

echo "==> Cleaning stale build artifacts"
rm -rf build medusa_security.egg-info

echo "==> Building wheel"
python3 -m build --wheel

# restore() runs here via trap before the gate inspects the wheel.

WHL="$(ls -t dist/*.whl | head -1)"
echo "==> Leak-gating $WHL"
LEAKS="$(unzip -l "$WHL" | grep -iE 'licensing|/api/|runtime|node_modules|medusa-vscode' || true)"
if [ -n "$LEAKS" ]; then
  echo "❌ LEAK DETECTED — refusing to ship $WHL:"
  echo "$LEAKS"
  rm -f "$WHL"
  exit 1
fi
echo "✅ Clean wheel: $WHL"
unzip -l "$WHL" | tail -1
