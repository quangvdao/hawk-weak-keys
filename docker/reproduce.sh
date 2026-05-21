#!/usr/bin/env bash
#
# End-to-end reproduction script for the HAWK weak-key artifact.
#
# Steps:
#   1. Re-derive every test vector from the deterministic recipe.
#   2. Confirm regenerated vectors are byte-identical to the shipped manifest.
#   3. Build and run the C reference verifier on every .rsp file.
#   4. Run the Python reference verifier on every .rsp file.
#   5. Print ARTIFACT REPRODUCIBLE iff all four steps succeeded.

set -euo pipefail

cd "$(dirname "$0")/.."

echo "=========================================================================="
echo "Step 1 / 5: Re-derive test vectors from deterministic recipe"
echo "=========================================================================="
TMPDIR="$(mktemp -d)"
python3 -m src.generate_vectors --out-dir "$TMPDIR"
echo "OK: regenerated into $TMPDIR"

echo
echo "=========================================================================="
echo "Step 2 / 5: Confirm regenerated vectors are byte-identical to manifest"
echo "=========================================================================="
diff -ru vectors/json "$TMPDIR/json"
diff -ru vectors/kat  "$TMPDIR/kat"
( cd vectors && shasum -a 256 -c SHA256SUMS )
echo "OK: byte-identical"

echo
echo "=========================================================================="
echo "Step 3 / 5: Build and run C reference verifier"
echo "=========================================================================="
make -C drivers
drivers/verify_kat vectors/kat/*.rsp
echo "OK: C reference accepts every record"

echo
echo "=========================================================================="
echo "Step 4 / 5: Run Python reference verifier"
echo "=========================================================================="
echo "(MBS / M-S-UEO: full check.  wNR: 5-record sample per parameter set,"
echo " since the pure-Python verifier is ~6-40s/record.  Use HAWK_WNR_FULL=1"
echo " to force a full Python check on all 100 wNR records per set.)"
echo
python3 drivers/verify_kat.py vectors/kat/mbs_hawk*.rsp vectors/kat/m_s_ueo_hawk*.rsp
WNR_MAX="${HAWK_WNR_PYTHON_SAMPLE:-5}"
if [ "${HAWK_WNR_FULL:-0}" = "1" ]; then
    python3 drivers/verify_kat.py vectors/kat/wnr_hawk*.rsp
else
    python3 drivers/verify_kat.py --max-records "$WNR_MAX" vectors/kat/wnr_hawk*.rsp
fi
echo "OK: Python reference accepts every checked record"

echo
echo "=========================================================================="
echo "ARTIFACT REPRODUCIBLE"
echo "=========================================================================="
