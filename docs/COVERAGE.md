# Coverage

CI resolves one fresh Cargo.lock and uses that snapshot for stable checks,
advisory policy and nightly LLVM branch instrumentation. Both line and branch
counts must be complete; any reachable gap fails the gate. No production source
is excluded. Only test harness files (`tests/` and `tests.rs`) are omitted from
the measured source; their actual round trips still execute.

A configured gate is not a coverage result. The raw report is retained on failure.

The coverage job exports raw JSON, LCOV and annotated source from the same actual test execution.
The gate requires every emitted production DA line and BRDA branch to have a
nonzero counter, at 100% for both metrics. It cross-checks file inventories,
summaries and emitted branch locations against the companion JSON. Missing,
duplicate, empty or malformed evidence cannot pass. Raw JSON totals remain
as diagnostic evidence for generic instantiations; source coverage does not
claim every generic instantiation is covered. All three reports are retained on
failure. No production source exclusions are currently approved.

The gate independently reconciles every emitted DA line and hit/miss with the
same-run annotated report. Removing an interior DA record cannot turn an
incomplete report green, even when generic summary totals differ. Duplicate raw
source records also refuse. Corruption tests run before accepting any report.
