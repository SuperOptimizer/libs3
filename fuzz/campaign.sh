#!/bin/sh
# 8-core AFL++ campaign on the libs3 parsers.
#
# Topology (AFL++ recommended multi-core mix):
#   m0  main (-M)            : coordinator, deterministic + havoc
#   s1  cmplog (-c)          : RedQueen / input-to-state, finds magic vals
#   s2  autotokens grammar   : token-level structural mutation (XML/JSON)
#   s3  autotokens + cmplog  : grammar + I2S together
#   s4  MOpt (-L0)           : MOpt mutator schedule
#   s5  explore  (-p explore): coverage-spreading power schedule
#   s6  exploit  (-p exploit): depth-first power schedule
#   s7  dict-only havoc      : heavy dictionary use
#
# All instances share the dictionary and sync via the output dir.
# Duration: $DURATION seconds (default 1800 = 30 min).
set -e
cd "$(dirname "$0")/.."

DUR="${DURATION:-1800}"
OUT="${OUT:-fuzz/findings}"
IN="${IN:-fuzz/corpus/seeds}"
DICT="fuzz/s3.dict"
BIN=./fuzz/fuzz_parsers_afl
CMPLOG=./fuzz/fuzz_parsers_cmplog
GRAM=fuzz/autotokens.so

rm -rf "$OUT"
mkdir -p "$OUT"

export AFL_I_DONT_CARE_ABOUT_MISSING_CRASHES=1
export AFL_SKIP_CPUFREQ=1
export AFL_NO_AFFINITY=1
export AFL_AUTORESUME=1

PIDS=""
launch() { # name, extra-args..., env-prefix handled by caller
    name="$1"; shift
    afl-fuzz -V "$DUR" -i "$IN" -o "$OUT" "$@" >"$OUT/$name.log" 2>&1 &
    PIDS="$PIDS $!"
    echo "  launched $name (pid $!)"
}

echo "[*] 8-core campaign, ${DUR}s"
launch m0   -M m0            -x "$DICT" -- "$BIN"
launch s1   -S s1 -c "$CMPLOG" -x "$DICT" -- "$BIN"
AFL_CUSTOM_MUTATOR_LIBRARY="$GRAM" \
  afl-fuzz -V "$DUR" -i "$IN" -o "$OUT" -S s2 -x "$DICT" -- "$BIN" \
    >"$OUT/s2.log" 2>&1 & PIDS="$PIDS $!"; echo "  launched s2 (grammar)"
AFL_CUSTOM_MUTATOR_LIBRARY="$GRAM" \
  afl-fuzz -V "$DUR" -i "$IN" -o "$OUT" -S s3 -c "$CMPLOG" -x "$DICT" -- "$BIN" \
    >"$OUT/s3.log" 2>&1 & PIDS="$PIDS $!"; echo "  launched s3 (grammar+cmplog)"
launch s4   -S s4 -L 0       -x "$DICT" -- "$BIN"
launch s5   -S s5 -p explore -x "$DICT" -- "$BIN"
launch s6   -S s6 -p exploit -x "$DICT" -- "$BIN"
launch s7   -S s7 -x "$DICT" -- "$BIN"

echo "[*] PIDS:$PIDS"
echo "[*] waiting ${DUR}s ..."
for p in $PIDS; do wait "$p" 2>/dev/null || true; done

echo "[*] campaign done. crash/hang summary:"
CR=$(find "$OUT" -path '*/crashes/id:*' 2>/dev/null | wc -l)
HG=$(find "$OUT" -path '*/hangs/id:*'   2>/dev/null | wc -l)
echo "    crashes=$CR hangs=$HG"
find "$OUT" -path '*/crashes/id:*' 2>/dev/null | head
exit 0
