#!/usr/bin/env bash
set -euo pipefail
# Merge stderr into the captured stdout stream: Crow preserves stdout only,
# and cargo/node diagnostics go to stderr (a silent exit 101 is undiagnosable).
exec 2>&1

export CARGO_BUILD_JOBS="${CARGO_BUILD_JOBS:-2}"
export CARGO_TERM_COLOR="${CARGO_TERM_COLOR:-always}"
export CARGO_HTTP_USER_AGENT="${CARGO_HTTP_USER_AGENT:-dependency-ci}"
export CARGO_NET_GIT_FETCH_WITH_CLI="${CARGO_NET_GIT_FETCH_WITH_CLI:-true}"

rustc --version
# Resolve dependency origin migration on CI and retain the exact candidate.
cargo update
cp Cargo.lock "$ARTIFACT_ROOT/Cargo.lock"
echo "STAGE: fmt"
cargo fmt --all --check
echo "STAGE: pins-test"
node --test .github/check-pins.test.mjs
echo "STAGE: metadata"
cargo metadata --locked --format-version 1 > dependency-metadata.json
echo "STAGE: pins-check"
node .github/check-pins.mjs dependency-metadata.json
echo "STAGE: clippy"
cargo clippy --locked --all-targets -- -D warnings
echo "STAGE: licenses"
cargo metadata --locked --format-version 1 | python3 -c 'import json,sys; d=json.load(sys.stdin); json.dump([{k:p.get(k) for k in ("name","version","license","source")} for p in d["packages"]],sys.stdout,indent=2)' > dependency-licenses.json
echo "STAGE: test"
cargo test --locked

echo "STAGE: first-party"
python3 .github/check-first-party.py

echo "STAGE: nightly"
rustup run nightly rustc --version
NIGHTLY_RUSTC="$(rustup which --toolchain nightly rustc)"
NIGHTLY_CARGO="$(rustup which --toolchain nightly cargo)"
NIGHTLY_BIN="$(dirname "$NIGHTLY_RUSTC")"
export RUSTC="$NIGHTLY_RUSTC"
export CARGO="$NIGHTLY_CARGO"
export PATH="$NIGHTLY_BIN:$PATH"
export RUSTUP_TOOLCHAIN=nightly
# Bug 2 isolation: coverage data must not reuse the shared cargo target
# across jobs (stale checkout paths fail the next gate); scope the
# coverage target to this job only. Native gates keep the shared warm
# target; outer traps and services are untouched.
(
coverage_target="$(mktemp -d)"
case "$coverage_target" in ""|"$PWD"/*) echo 'unsafe coverage target' >&2; exit 2;; esac
trap 'rm -rf -- "$coverage_target"' EXIT
export CARGO_TARGET_DIR="$coverage_target"
echo "STAGE: llvm-cov-version"
"$NIGHTLY_CARGO" llvm-cov --version
echo "STAGE: llvm-cov-json"
"$NIGHTLY_CARGO" llvm-cov --locked --workspace --all-features --branch --no-cfg-coverage --no-cfg-coverage-nightly --ignore-filename-regex '(/tests/|/tests\.rs$)' --json --output-path coverage.json
echo "STAGE: llvm-cov-lcov"
"$NIGHTLY_CARGO" llvm-cov report --locked --branch --ignore-filename-regex '(/tests/|/tests\.rs$)' --lcov --output-path coverage.lcov
)
echo "STAGE: coverage-soft"
python3 .github/check-coverage.py coverage.json || true
echo "STAGE: coverage-gate"
python3 .github/check-source-coverage.py coverage.lcov coverage.json
echo "STAGE: done"
