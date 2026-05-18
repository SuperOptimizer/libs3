# libs3

A minimal **C23** S3 client: a small replacement for the S3 subset of the
AWS SDK. One header (`libs3.h`) + one source file (`libs3.c`). The only hard
dependency is **libcurl** (>= 7.75 for built-in SigV4). JSON and XML are
parsed by tiny internal scrapers — no extra libraries.

## Capabilities

- Object ops: `GET`, byte-range `GET`, conditional `GET` (`If-None-Match`
  → 304), `HEAD`, `PUT`, streamed `PUT` from file, `DELETE`, server-side
  `COPY`
- Batched ranged `GET` via `curl_multi` — many chunk fetches concurrently
  over pooled connections (the hot path for zarr rendering)
- Multipart upload (`create` / `upload_part` / streamed `upload_part_file`
  / `complete` / `abort`); parts stream from disk in constant memory
- `ListObjectsV2` with delimiter, `max-keys`, `start-after`, and
  auto-pagination (`s3_list` / `s3_list_ex` / `s3_list_all`)
- Response metadata exposed: `ETag`, `Last-Modified`, `Content-Length`
- `s3://`, `S3://`, and `s3+REGION://` URL forms → virtual-hosted HTTPS
- Non-AWS endpoint override (path-style) for MinIO / localstack
- Full AWS credential resolution: explicit/`$AWS_PROFILE` →
  `aws configure export-credentials` → EC2 IMDSv2 (cached in-process,
  refreshed before expiry, no `aws` fork-storm) → SSO profiles in
  `~/.aws/config` → `~/.aws/credentials`/`config` INI → environment
- AWS SigV4 signing via libcurl; anonymous when no credentials
- Per-request refresh-aware credential provider (survives multi-hour STS
  rotation on long-running EC2 jobs)
- Exponential-backoff retry (5xx / 401 / 403 / network) with jitter
- Process-wide fast abort for instant shutdown regardless of S3 timeouts
- Thread-safe: shared client, thread-local reused curl handle (keeps the
  connection pool / TLS sessions warm across calls)

## Build

```sh
cmake -S . -B build
cmake --build build
ctest --test-dir build               # url + parser unit tests
LIBS3_LIVE=1 ./build/test_live_s3    # opt-in live S3 test
cmake -S . -B build-asan -DLIBS3_ASAN=ON   # ASAN/UBSAN build

# coverage report (build-cov/coverage/index.html + text summary)
cmake -S . -B build-cov -DLIBS3_COVERAGE=ON
cmake --build build-cov --target coverage
```

All tests link one instrumented library instance, so the lcov number is
the true union across the whole suite. With every test active:

```sh
sh test/minio-up.sh                       # local MinIO + test bucket
cd build-cov && LIBS3_LIVE=1 LIBS3_MINIO=1 ctest
```

reaches **~97% line / ~99% function** coverage of `libs3.c`. The IMDSv2
credential path is covered without any AWS by `test_imds_mock`, which
spins up a local metadata server and points libs3 at it via
`$LIBS3_IMDS_BASE` (exercising the token/role/creds fetch, the
in-process cache, refresh-before-expiry, and stale-cache fallback). The
remaining ~3% is genuinely unreachable in a test: a pthread thread-exit
destructor, allocator-failure (OOM) guards, the `aws` CLI / SSO
`export-credentials` body, retry/`curl_multi` transport-error mapping
(needs a flaky server), and non-conformant S3 responses.

### Real-EC2 IMDS test (optional)

`test_imds_ec2` is gated behind `LIBS3_IMDS=1` and runs *on* an EC2
instance with an attached IAM role. It resolves instance-role
credentials via the genuine `169.254.169.254` IMDSv2, then proves they
sign correctly with a real SigV4 GET (and, with
`LIBS3_IMDS_WRITE_PREFIX=s3://bucket/prefix`, a PUT/GET/DELETE
round-trip). Verified on aarch64 against an EC2 instance role scoped
to a write-restricted bucket prefix.

Builds `libs3.a` and `libs3.so`, plus the `cat_object` and `list_bucket`
examples.

### Fuzzing

The response parsers (`xml_tag`/list-XML, `json_string_field`,
`s3_url_parse`, `url_decode_inplace`) consume untrusted S3/IMDS bytes
and are fuzzed via a libFuzzer-API harness (`fuzz/fuzz_parsers.c`):

```sh
sh fuzz/build.sh                                   # native libFuzzer
./fuzz/fuzz_parsers -max_total_time=300 fuzz/corpus/seeds
AFL=1 sh fuzz/build.sh && DURATION=1800 sh fuzz/campaign.sh   # AFL++ fleet
```

`campaign.sh` runs an 8-core AFL++ fleet (RedQueen/cmplog, the
`autotokens` grammar mutator, MOpt, explore/exploit power schedules, and
an S3/IMDS dictionary) seeded from real ListObjectsV2 / multipart XML and
IMDS-shaped JSON. A native-libFuzzer run (1.5M+ execs) plus the full
multi-technique AFL++ campaign found **zero crashes, hangs, or
sanitizer errors**.

## Quick start

```c
#include "libs3.h"

s3_client *c = s3_client_new(NULL);          /* anonymous */
s3_response r = {0};
if (s3_get(c, "s3://my-bucket/key.bin", &r) == S3_OK && s3_response_ok(&r))
    fwrite(r.body, 1, r.body_len, stdout);
s3_response_free(&r);
s3_client_free(c);
```

For signed access, fill `s3_config.creds` (e.g. via `s3_credentials_load`)
or set `s3_config.cred_provider` for long-running jobs.

## Not in v1

- Presigned URLs (libcurl's built-in SigV4 can't sign query params — would
  need a hand-rolled signer; documented extension point)
- Bucket lifecycle ops (create/delete bucket, policy, ACL, versioning)
- S3 Select / Glacier restore / Object Lock / batch operations
- Async transfer manager beyond the batched ranged GET (callers
  parallelize their own work as volume-cartographer does)

## Status

Covers the S3 functionality
[volume-cartographer](https://github.com/) uses (replacing its
`http_fetch.hpp` / `aws_auth.cpp`) plus write/multipart/delete/copy,
parallel multipart, batched ranged GET, conditional GET, If-Match
optimistic-concurrency PUT, and a MinIO-compatible endpoint override.

Verified building warning-free under `-Wall -Wextra -Wpedantic
-std=c23`; clean under **ASan, UBSan, ThreadSanitizer, and
TypeSanitizer** across the full suite (live
`vesuvius-challenge-open-data` reads + Docker-MinIO write/multipart +
mock & real-EC2 IMDSv2 + a 16-thread shared-client concurrency stress),
on both x86-64 and aarch64, at ~97% line / ~99% function coverage. The
untrusted-input parsers are fuzzed (libFuzzer + an 8-core AFL++ fleet)
with zero findings. Static analysis (clang analyzer + clang-tidy) is
clean.
