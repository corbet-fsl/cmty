# cmty agent notes

Work in a lane (`~/agents/scratch/lane-new <lane>`); never edit `~/agents/scratch/ws`.
Run from the lane root (`<lane>/ws`); `cbuild <lane> ...` builds there.

Build and test (quote the verdict line, never infer from a pipe):
- `cbuild <lane> fmt -p cmty -- --check` — must be clean
- `cbuild <lane> test -p cmty --locked --test community --test certificates --test root_board --test root_issuance --test storage` — lib `22`, `community` `46`, `certificates` `3`, `root_board` `4`, `root_issuance` `13`, `storage` `2` passed, exit 0; long, background it
- `test --test accounting` needs `CBLC_PROOF_DIRECTORY` (CI-only signed artifacts); without it `8` pass and `11` fail at the env gate in `tests/accounting/*/native.rs`
- `cbuild <lane> clippy -p cmty --locked --all-targets -- -D warnings` — red at HEAD from upstream `ckmg` lints (unused `SigningPhase`, dead `label`/`insert`), not this crate
- Full gate (first-party refresh, live Turso run, coverage) runs in CI; see `.github/workflows/ci.yml`, `docs/COVERAGE.md`.

Land: `cargo fmt` in touched repos, rebase on main (never force-push),
`cbuild <lane> xtask land --dry`, then `xtask land`.

Invariants (rule -> enforcing test):
- `cplc` alone decides admission; `cmty` holds no policy or lifetime logic
  -> `tests/community.rs::mismatched_checked_gate_receipts_fail_in_cgts`, `::transient_gates_run_through_cgts_and_do_not_become_reusable_facts`
- A legal veto blocks issuance even under a permissive policy
  -> `::legal_veto_blocks_issuance_even_with_permissive_policy`
- Replay and concurrent submissions return at most one credential
  -> `::replay_and_concurrent_submissions_return_at_most_one_credential`
- A released member cannot renew; handle release stays with `cmbr`
  -> `::released_member_cannot_renew_and_handle_release_stays_with_cmbr`
- Lifetimes follow gate/passport/revision; withdrawal lapses, fresh gates readmit
  -> `::lifetime_adapts_to_gate_policy_passport_and_scheduled_revision`, `::gate_withdrawal_lapses_membership_and_fresh_gate_readmits`, `::gate_expiry_lapses_membership_at_the_exclusive_deadline`

Pointers: `src/community.rs`, `src/adapters.rs`, `docs/CONTRACT.md`, `docs/COVERAGE.md`.
Commits: explicit paths, imperative, author per `~/agents/AGENT.md`; no AI trailers.
`publish=false`; FSL-1.1-ALv2; no GPL/AGPL-only deps.
