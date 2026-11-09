#!/bin/bash
# Bismillah ir-Rahman ir-Rahim
#
# Sync furqan-lint standalone package from the Kun Fayakun monorepo.
# Run this from the furqan-lint/ directory before building.
#
# Bismillah ir-Rahman ir-Rahim

set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"
MONO_CHECKS="../src/kun_fayakun/furqan/checks"
STANDALONE="$SCRIPT_DIR/src/furqan_lint"

echo "Bismillah ir-Rahman ir-Rahim"
echo ""
echo "Syncing furqan-lint from monorepo..."

# Core check modules
for f in finding.py config.py formatters.py runner.py \
         ring_close.py marad.py trust_boundary.py scan_incomplete.py \
         secrets.py injection.py crypto.py; do
    # Rewrite imports from kun_fayakun.furqan.checks -> furqan_lint
    sed 's/kun_fayakun\.furqan\.checks/furqan_lint/g' "$MONO_CHECKS/$f" > "$STANDALONE/$f"
    echo "  $f"
done

# Adapters
mkdir -p "$STANDALONE/adapters"
for f in __init__.py base.py c_adapter.py cpp_adapter.py \
         java_adapter.py csharp_adapter.py ada_adapter.py; do
    sed 's/kun_fayakun\.furqan\.checks/furqan_lint/g' "$MONO_CHECKS/adapters/$f" > "$STANDALONE/adapters/$f"
    echo "  adapters/$f"
done

# Copy README
cp "$MONO_CHECKS/README.md" "$SCRIPT_DIR/README.md"
echo "  README.md"

echo ""
echo "Sync complete."
echo ""
echo "Bismillah ir-Rahman ir-Rahim"
