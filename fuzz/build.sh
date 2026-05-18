#!/bin/sh
# Build the parser fuzzer (libFuzzer entry point LLVMFuzzerTestOneInput).
# Two flavours:
#   AFL=1  -> AFL++ instrumented (afl-clang-fast, for afl-fuzz)
#   else   -> native clang libFuzzer (-fsanitize=fuzzer, standalone)
# Both add ASan+UBSan so memory/UB on malformed S3/IMDS responses fail.
#
#   sh fuzz/build.sh           # libFuzzer:  ./fuzz/fuzz_parsers corpus/seeds
#   AFL=1 sh fuzz/build.sh     # AFL++:      see run command printed below
#
# AFL++ must be the git/dev build against the installed LLVM (the stable
# tag's SanitizerCoverage pass ICEs on LLVM >= 21). clang-21 is pinned
# via AFL_CC so AFL's pass and the compiler agree on LLVM version.
set -e
cd "$(dirname "$0")/.."

SAN="-fsanitize=fuzzer,address,undefined -fno-omit-frame-pointer"

if [ "${AFL:-0}" = "1" ]; then
    : "${AFL_CC:=clang-21}"
    export AFL_CC
    # Link AFL++'s libFuzzer driver (proper forkserver) -- NOT clang's
    # -fsanitize=fuzzer, which doesn't drive correctly under parallel
    # -M/-S afl-fuzz. ASan+UBSan still on. Plus a CMPLOG twin.
    DRIVER="${AFLPP_DRIVER:-/tmp/AFLplusplus/libAFLDriver.a}"
    [ -f "$DRIVER" ] || { echo "need libAFLDriver.a (AFLPP_DRIVER=...)"; exit 1; }
    AFLSAN="-fsanitize=address,undefined -fno-omit-frame-pointer"
    AFL_QUIET=1 afl-clang-fast -std=c23 -g -O1 -DLIBS3_TESTING $AFLSAN \
        -I. libs3.c fuzz/fuzz_parsers.c "$DRIVER" -lcurl -lpthread \
        -o fuzz/fuzz_parsers_afl
    AFL_QUIET=1 AFL_LLVM_CMPLOG=1 afl-clang-fast -std=c23 -g -O1 \
        -DLIBS3_TESTING $AFLSAN -I. libs3.c fuzz/fuzz_parsers.c \
        "$DRIVER" -lcurl -lpthread -o fuzz/fuzz_parsers_cmplog
    echo "built fuzz/fuzz_parsers_afl + _cmplog (AFL++ driver / LLVM-21)"
    echo "run: DURATION=1800 sh fuzz/campaign.sh   (8-core fleet)"
else
    clang-21 -std=c23 -g -O1 -DLIBS3_TESTING $SAN \
        -I. libs3.c fuzz/fuzz_parsers.c -lcurl -lpthread \
        -o fuzz/fuzz_parsers
    echo "built fuzz/fuzz_parsers (clang libFuzzer)"
    echo "run: ./fuzz/fuzz_parsers -max_total_time=300 fuzz/corpus/seeds"
fi
