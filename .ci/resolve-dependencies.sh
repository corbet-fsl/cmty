#!/usr/bin/env bash
# Resolve the changed integration graph; this is not a validation verdict.
set -euo pipefail
exec 2>&1
: "${ARTIFACT_ROOT:?Missing retained artifact destination}"
: "${CI_COMMIT_SHA:?Missing verified source revision}"
[[ "$ARTIFACT_ROOT" = /* && "$CI_COMMIT_SHA" =~ ^[0-9a-f]{40}$ ]] || exit 2
cargo update -p cblc -p cpmt -p cvfy -p czkp -p cgts -p cplc -p cmbr
cargo metadata --locked --format-version 1 > dependency-metadata.json
resolved="$ARTIFACT_ROOT/$CI_COMMIT_SHA/resolve-dependencies"
mkdir -p "$resolved"
cp Cargo.lock dependency-metadata.json "$resolved/"
echo ---LOCK-BEGIN---; cat Cargo.lock; echo ---LOCK-END---
sha256sum Cargo.lock dependency-metadata.json
echo 'Resolved inputs only; review exact upstream revisions, commit the lock and run verify.'
